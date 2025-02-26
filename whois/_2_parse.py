import re
import sys

from typing import Any, Dict, Optional, List

from .exceptions import FailedParsingWhoisOutput
from .exceptions import WhoisQuotaExceeded

from . import tld_regexpr

Verbose = True

TLD_RE: Dict[str, Any] = {}


def get_tld_re(tld: str) -> Any:
    if tld in TLD_RE:
        return TLD_RE[tld]

    if tld == "in":
        # is this actually used ?
        if Verbose:
            print("Verbose: directly returning tld: in_ for tld: in", file=sys.stderr)
        return "in_"

    v = getattr(tld_regexpr, tld)

    extend = v.get("extend")
    if extend:
        e = get_tld_re(extend)  # call recursive
        tmp = e.copy()
        tmp.update(v)  # and merge results in tmp with caller data in v
        # The update() method updates the dictionary with the elements
        # from another dictionary object or from an iterable of key/value pairs.
    else:
        tmp = v

    # finally we dont want to propagate the extend data
    # as it is only used to recursivly populate the dataset
    if "extend" in tmp:
        del tmp["extend"]

    # we want now to exclude _server hints
    tld_re = dict(
        (k, re.compile(v, re.IGNORECASE) if (isinstance(v, str) and k[0] != "_") else v) for k, v in tmp.items()
    )

    # meta domains start with _: examples _centralnic and _donuts
    if tld[0] != "_":
        TLD_RE[tld] = tld_re

    return tld_re


# now fetch all defined data in
# The dir() method returns the list of valid attributes of the passed object

[get_tld_re(tld) for tld in dir(tld_regexpr) if tld[0] != "_"]


def cleanupWhoisResponse(
    whois_str: str,
    verbose: bool = False,
    with_cleanup_results: bool = False,
) -> str:
    tmp2 = []

    # note we cannot do yet rstrip() on the lines as many registrars use \r and even trailing whitespace after entries
    # as the resulting matches are all stripped of leading and trailing whitespace this currently is fixed there
    # and relaxes the regexes: you will often see a capture with (.*)
    # we would have to fix all regexes to allow stripping all trailing whitespace
    # it would make many matches easier though.

    skipFromHere = False
    tmp: List = whois_str.split("\n")
    for line in tmp:
        if skipFromHere is True:
            continue

        # some servers respond with: % Quota exceeded in the comment section (lines starting with %)
        if "quota exceeded" in line.lower():
            raise WhoisQuotaExceeded(whois_str)

        if with_cleanup_results is True and line.startswith("%"):  # only remove if requested
            continue

        if "REDACTED FOR PRIVACY" in line:  # these lines contibute nothing so ignore
            continue

        if (
            "Please query the RDDS service of the Registrar of Record" in line
        ):  # these lines contibute nothing so ignore
            continue

        # regular responses may at the end have meta info starting with a line >>> some texte <<<
        # similar trailing info exists with lines starting with -- but we wil handle them later
        # unfortunalery we have domains (google.st) that have this early at the top
        if 0:
            if line.startswith(">>>"):
                skipFromHere = True
                continue

        if line.startswith("Terms of Use:"):  # these lines contibute nothing so ignore
            continue

        tmp2.append(line.strip("\r"))

    return "\n".join(tmp2)


def handleShortResponse(
    tld: str,
    dl: List,
    whois_str: str,
    verbose: bool = False,
):  # returns None or raises one of (WhoisQuotaExceeded, FailedParsingWhoisOutput)
    if verbose:
        d = ".".join(dl)
        print(f"line count < 5:: {tld} {d} {whois_str}", file=sys.stderr)

    s = whois_str.strip().lower()

    # NOTE: from here s is lowercase only
    # ---------------------------------
    noneStrings = [
        "not found",
        "no entries found",
        "status: free",
        "no such domain",
        "the queried object does not exist",
        "domain you requested is not known",
        "status: available",
    ]

    for i in noneStrings:
        if i in s:
            return None

    # ---------------------------------
    # is there any error string in the result
    if s.count("error"):
        return None

    # ---------------------------------
    quotaStrings = [
        "limit exceeded",
        "quota exceeded",
        "try again later",
        "please try again",
        "exceeded the maximum allowable number",
        "can temporarily not be answered",
        "please try again.",
        "queried interval is too short",
    ]

    for i in quotaStrings:
        if i in s:
            raise WhoisQuotaExceeded(whois_str)

    # ---------------------------------
    # ToDo:  Name or service not known

    # ---------------------------------
    raise FailedParsingWhoisOutput(whois_str)


def doDnsSec(whois_str: str) -> bool:
    whois_dnssec: Any = whois_str.split("DNSSEC:")
    if len(whois_dnssec) >= 2:
        whois_dnssec = whois_dnssec[1].split("\n")[0]
        if whois_dnssec.strip() == "signedDelegation" or whois_dnssec.strip() == "yes":
            return True
    return False


def doIfServerNameLookForDomainName(whois_str: str, verbose: bool = False) -> str:
    # not often available anymore
    if re.findall(r"Server Name:\s?(.+)", whois_str, re.IGNORECASE):
        if verbose:
            msg = "i have seen Server Name:, looking for Domain Name:"
            print(msg, file=sys.stderr)
        whois_str = whois_str[whois_str.find("Domain Name:") :]
    return whois_str


def doExtractPattensIanaFromWhoisString(tld: str, r: Dict, whois_str: str, verbose: bool = False):
    # now handle the actual format if this whois response
    iana = {
        "domain_name": r"domain:\s?([^\n]+)",
        "registrar": r"organisation:\s?([^\n]+)",
        "creation_date": r"created:\s?([^\n]+)",
    }
    for k, v in iana.items():
        zz = re.findall(v, whois_str)
        if zz:
            if verbose:
                print(tld, zz, file=sys.stderr)
            r[k] = zz
    return r


def doSourceIana(tld: str, r: Dict, whois_str: str, verbose: bool = False) -> str:
    # here we can handle the example.com and example.net permanent IANA domains

    if verbose:
        msg = "i have seen source: IANA"
        print(msg, file=sys.stderr)

    whois_splitted = whois_str.split("source:       IANA")
    if len(whois_splitted) == 2 and whois_splitted[1].strip() != "":
        # if we see source: IANA and the part after is not only whitespace
        if verbose:
            msg = f"after IANA: {whois_splitted[1]}"
            print(msg, file=sys.stderr)

        return whois_splitted[1], None

    # try to parse this as a IANA domain as after is only whitespace
    r = doExtractPattensFromWhoisString(tld, r, whois_str, verbose)  # set default values

    # now handle the actual format if this whois response
    r = doExtractPattensIanaFromWhoisString(tld, r, whois_str, verbose)

    return whois_str, r


def doExtractPattensFromWhoisString(tld: str, r: Dict, whois_str: str, verbose: bool = False):
    for k, v in TLD_RE.get(tld, TLD_RE["com"]).items():  # use TLD_RE["com"] as default if a regex is missing
        if k.startswith("_"):  # skip meta element like: _server or _privateRegistry
            continue

        # Historical: here we use 'empty string' as default, not None
        if v is None:
            r[k] = [""]
        else:
            r[k] = v.findall(whois_str) or [""]

    return r


def do_parse(
    whois_str: str,
    tld: str,
    dl: List[str],
    verbose: bool = False,
    with_cleanup_results=False,
) -> Optional[Dict[str, Any]]:

    whois_str = cleanupWhoisResponse(
        whois_str=whois_str,
        verbose=verbose,
        with_cleanup_results=with_cleanup_results,
    )

    if whois_str.count("\n") < 5:
        return handleShortResponse(tld, dl, whois_str, verbose)

    r: Dict[str, Any] = {
        "tld": tld,
        "DNSSEC": doDnsSec(whois_str),
    }

    if "source:       IANA" in whois_str:  # prepare for handling historical IANA domains
        whois_str, ianaDomain = doSourceIana(tld, r, whois_str, verbose)
        if ianaDomain is not None:
            return ianaDomain

    if "Server Name" in whois_str:  # handle old type Server Name (not very common anymore)
        whois_str = doIfServerNameLookForDomainName(whois_str, verbose)

    return doExtractPattensFromWhoisString(tld, r, whois_str, verbose)
