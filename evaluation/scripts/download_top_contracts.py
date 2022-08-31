
import re
import time
import json
import cfscrape

ETHERSCAN_API_TOKEN = "VZ7EMQBT4GNH5F6FBV8FKXAFF6GS4MPKAU"
MAX_CONTRACTS = 100

def main():
    scraper = cfscrape.create_scraper()
    page = 1
    items_per_page = 100
    contracts = list()
    while len(contracts) != MAX_CONTRACTS:
        print("Requesting", "https://etherscan.io/accounts/"+str(page)+"?ps="+str(items_per_page))
        content = scraper.get("https://etherscan.io/accounts/"+str(page)+"?ps="+str(items_per_page)).content.decode('utf-8')
        rows = re.compile("<tr>(.+?)</tr>").findall(content)
        for row in rows:
            columns = re.compile("<td>(.+?)</td>").findall(row)
            if columns[1].startswith("<span"):
                address = re.compile("<a href=.+?>(.+?)</a>").findall(columns[1])[0]
                print(" --> Getting contract info", "https://api.etherscan.io/api?module=contract&action=getsourcecode&address="+address+"&apikey="+ETHERSCAN_API_TOKEN)
                time.sleep(1)
                contract_info = scraper.get("https://api.etherscan.io/api?module=contract&action=getsourcecode&address="+address+"&apikey="+ETHERSCAN_API_TOKEN).json()
                if contract_info["status"] == "1" and contract_info["message"] == "OK" and len(contract_info["result"]) == 1:
                    # Ignore contracts without source code and where the source code is not solidity
                    if contract_info["result"][0]["ABI"] != "Contract source code not verified" and not "vyper" in contract_info["result"][0]["CompilerVersion"]:
                        minor = int(contract_info["result"][0]["CompilerVersion"].replace("v", "").split(".")[1])
                        patch = int(contract_info["result"][0]["CompilerVersion"].replace("v", "").split(".")[2].split("-")[0].split("+")[0])
                        # Ignore contracts that were compiled before 0.5.13
                        if minor > 5 or minor == 5 and patch >= 13:
                            # Ignore contracts that consist of multiple files
                            if not contract_info["result"][0]["SourceCode"].startswith("{"):
                                contract = {
                                    "Rank": int(columns[0]),
                                    "Address": address,
                                    "NameTag": columns[-4] if not "</a>" in columns[-4] else "",
                                    "Balance": float(re.compile("(.+?)<b>.</b><span class='text-secondary'>(.+?)</span> Ether").findall(columns[-3])[0][0].replace("</td><td>", "").replace(",", "")+"."+re.compile("(.+?)<b>.</b><span class='text-secondary'>(.+?)</span> Ether").findall(columns[-3])[0][1]) if "text-secondary" in columns[-3] else float(re.compile("(.+?) Ether").findall(columns[-3])[0].replace("</td><td>", "").replace(",", "")),
                                    "Percentage": float(columns[-2].replace("%", "")),
                                    "TxCount": int(columns[-1].replace(",", "")),
                                }
                                contract.update(contract_info["result"][0])
                                contracts.append(contract)
                else:
                    print("Error:", contract_info)
            if len(contracts) == MAX_CONTRACTS or page == 100:
                break
        print("Found", len(contracts), "contract(s) so far...")
        page += 1
    with open("top_contracts.json", "w") as f:
        json.dump(contracts, f)

if __name__ == "__main__":
    main()
