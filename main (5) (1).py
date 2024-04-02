import subprocess

subprocess.run("py -m pip install -U --user whoisdomain", shell=True, check=True)

import json

import whoisdomain
from whoisdomain.exceptions import WhoisPrivateRegistry


def get_whois(domain):
    try:
        r = whoisdomain.query(domain)
        return {k: v for k, v in r.__dict__.items()}
    except WhoisPrivateRegistry:
        # Handle domains that cannot be queried due to private registry issues
        return {"error": "Private registry or protected WHOIS information."}


def flatten_json(y):
    def flatten(x, name=""):
        if type(x) is dict:
            for a in x:
                flatten(x[a], f"{name}{a}_")
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, f"{name}{str(i)}_")
                i += 1
        else:
            out[name[:-1]] = x

    out = {}
    flatten(y)
    return out


if __name__ == "__main__":
    with open("input.json") as input_file:
        input_data = json.load(input_file)
    urls = input_data["input"]

    results = []
    for i, url in enumerate(urls, start=1):
        print(f"{i}/{len(urls)} {url=}")

        url = url.replace("https://", "").replace("http://", "")
        r = get_whois(url)
        if r:
            fj = flatten_json(r)
            fj["domain_name_0"] = url
            results.append(fj)
        else:
            results.append(
                {
                    "domain_name_0": url,
                    "domain_name_1": "Error",
                }
            )

        with open("output.json", "w") as output_file:
            json.dump(results, output_file, ensure_ascii=False, indent=2, default=str)
