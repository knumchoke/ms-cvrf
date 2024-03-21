import requests
import sys
import os
import json
import pandas as pd
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows


def formatCVRF(json_data):
    table_data = []
    for item in json_data:
        release_number = item["releaseNumber"]
        cve_number = item["cveNumber"]
        product = item["product"]

        if "platform" in item:
            platform = item["platform"]
        else:
            platform = "-"

        kb_articles = item.get(
            "kbArticles", []
        )  # Get the "kbArticles" array or an empty list if it doesn't exist
        for kb_article in kb_articles:
            article_name = kb_article["articleName"]
            article_url = kb_article["articleUrl"]
            download_name = kb_article["downloadName"]
            download_url = kb_article.get("downloadUrl", "")
            # table_data.append([release_number, product_family, cve_number, product, platform, article_name, download_name, download_url])
            table_data.append(
                [
                    release_number,
                    cve_number,
                    product,
                    platform,
                    article_name,
                    article_url,
                    download_name,
                    download_url,
                ]
            )
    # Create a DataFrame
    # df = pd.DataFrame(table_data, columns=['Release Number', 'Product Family', 'CVE Number', 'Product', 'Platform', 'Article Name', 'Download Name', 'Download URL'])
    df = pd.DataFrame(
        table_data,
        columns=[
            "Release Number",
            "CVE Number",
            "Product",
            "Platform",
            "Article Name",
            "Article URL",
            "Download Name",
            "Download URL",
        ],
    )
    return df


def createCVRFDB(cve, folder):
    database = []
    urlFolder = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=(releaseNumber eq '{}')".format(
        folder
    )
    headers = {"Accept": "application/json"}
    response = requests.get(urlFolder, headers=headers)
    data = response.json()

    if not os.path.isdir("json/" + folder):
        os.mkdir("json/" + folder)

    if not os.path.isdir("csv/" + folder):
        os.mkdir("csv/" + folder)

    with open("json/" + folder + "/" + folder + ".json", "w") as file:
        json.dump(data, file, indent=4)

    cvrfData = data["value"]
    # dictCvrfData = json.loads(cvrfData)
    allCVE = [item["cveNumber"] for item in cvrfData]
    tmaCVElist = getCVEHardList(cve)

    intersected_cve_array = list(set(allCVE) & set(tmaCVElist))
    intersected = [x for x in cvrfData if x["cveNumber"] in intersected_cve_array]
    with open("json/" + folder + "/" + "intersected" + ".json", "w") as file:
        json.dump(intersected, file, indent=4)

    onlyCVRF_cve_array = list(set(allCVE) - set(tmaCVElist))
    onlyCVRF = [x for x in cvrfData if x["cveNumber"] in onlyCVRF_cve_array]
    with open("json/" + folder + "/" + "onlyCVRF" + ".json", "w") as file:
        json.dump(onlyCVRF, file, indent=4)

    onlyTMA_cve_array = list(set(tmaCVElist) - set(allCVE))
    onlyTMA = createCVRFDBfromCVE(onlyTMA_cve_array)
    with open("json/" + folder + "/" + "onlyTMA" + ".json", "w") as file:
        json.dump(onlyTMA, file, indent=4)

    database.extend(intersected)
    database.extend(onlyCVRF)
    database.extend(onlyTMA)
    with open("json/" + folder + "/" + "database" + ".json", "w") as file:
        json.dump(database, file, indent=4)

    table_data = formatCVRF(database)
    table_data.to_csv(
        "csv/" + folder + "/database" + ".csv",
        index=False,
        quotechar='"',
        sep="\t",
    )
    return [len(intersected_cve_array), len(onlyCVRF_cve_array), len(onlyTMA_cve_array)]


def split_array_into_chunks(arr, chunk_size):
    for i in range(0, len(arr), chunk_size):
        yield arr[i : i + chunk_size]


def convert_array_to_string(arr):
    return "('" + "','".join(arr) + "')"


def createCVRFDBfromCVE(cve_array):
    chunk_size = 50
    database = []
    for chunk in split_array_into_chunks(cve_array, chunk_size):
        converted_string = convert_array_to_string(chunk)
        url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=(cveNumber in {})".format(
            converted_string
        )
        headers = {"Accept": "application/json"}
        response = requests.get(url, headers=headers)
        data = response.json()
        responseData = data["value"]
        database.extend(responseData)
    return database


def getCVEHardList(fileName):
    try:
        with open(fileName, "r") as file:
            # Reading each line and storing it in a list
            lines = [line.strip() for line in file]
        return lines
    except FileNotFoundError:
        print(f"{fileName} not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []


if __name__ == "__main__":
    cve = sys.argv[1]
    folder = sys.argv[2]
    # a = getCVEHardList("cvelist.txt")
    cvrfData = createCVRFDB(cve, folder)
    csv_file = "csv/" + folder + "/database.csv"
    xlsx_file = folder + "-database.xlsx"
    df = pd.read_csv(csv_file, sep="\t")
    df.to_excel(xlsx_file, index=False, engine="openpyxl")
    # print(df)
    print("Done")
