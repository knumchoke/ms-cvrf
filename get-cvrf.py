import requests
import pandas as pd
import sys
import json
import glob
import os
import csv
import time
from openpyxl.utils.dataframe import dataframe_to_rows


def getCVRF(folder, cve):
    url = f"https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter="
    strCVE = "(cveNumber eq '{}')".format(cve)
    # url = "".join([url, strId, strCVE])
    url = "".join([url, strCVE])
    print(url)
    headers = {"Accept": "application/json"}
    response = requests.get(url, headers=headers)
    data = response.json()
    if not os.path.isdir("json/" + folder):
        os.mkdir("json/" + folder)

    with open("json/" + folder + "/" + cve + ".json", "w") as file:
        json.dump(data, file, indent=4)
    time.sleep(0.5)
    return data


def readCVRFfromFile(folder, cve):
    with open("json/" + folder + "/" + cve + ".json") as file:
        json_data = json.load(file)
    return json_data


def formatCVRF(json_data):
    table_data = []
    for item in json_data["value"]:
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


def getCVElist(fileName):
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


def mergecsv(folder):
    file_list = glob.glob(os.path.join("csv/" + folder, "*.csv"))
    if not file_list:
        print(f"No CSV files found in {'csv/' + folder}.")
        return
    try:
        with open("CVE-all.csv", "w", newline="") as outfile:
            writer = None  # Initialize writer variable
            for i, filename in enumerate(file_list):
                with open(filename, "r") as infile:
                    reader = csv.reader(infile)
                    # Read the header from the first file
                    if i == 0:
                        header = next(reader)
                        writer = csv.writer(outfile)
                        writer.writerow(header)
                    # Skip header from subsequent files
                    else:
                        next(reader)
                    # Write the rows from the current file to the output file
                    writer.writerows(reader)
        print(f"Files have been merged to {'CVE-all.csv'}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def csvToXlsx(input, output):
    data = pd.read_csv(input, sep='\t')
    try:
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            data.to_excel(writer, index=False)
        print(f"Files have been converted to " + output)
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            "Usage: python get-cvrf.py <mode> <CVE> <folder>"
            + '\r\nmode   : "download" will download json CVE data'
            '\r\n       : "read" will convert json from `download mode to` csv'
            '\r\n       : "batch" will run download and read using cve list from text file'
            "\r\nCVE    : is CVE number in format CVE-yyyy-nnnnn"
            '\r\nfolder : folder that this script will write the file to, upto the running mode, "download" will write to json, "read" will write to csv, "batch" will write to both folder'
        )
    else:
        mode = sys.argv[1]
        cve = sys.argv[2]
        folder = sys.argv[3]
        if mode == "download":
            data = getCVRF(folder, cve)
            print("data exported to " + folder + "/" + cve + ".json")
        elif mode == "read":
            json_data = readCVRFfromFile(folder, cve)
            table_data = formatCVRF(json_data)
            # print(table_data)
            table_data.to_csv(
                "csv/" + folder + "/output-" + cve + ".csv",
                index=False,
                quotechar='"',
                sep="\t",
            )
            print("data exported to " + folder + "/" + cve + ".json")
        elif mode == "batch":
            print("running in batch mode")
            cveList = getCVElist(cve)
            # print(cveList)
            if not os.path.isdir("csv/" + folder):
                os.mkdir("csv/" + folder)

            for line in cveList:
                data = getCVRF(folder, line)
                # print(data)
                json_data = readCVRFfromFile(folder, line)
                # print(json_data)
                table_data = formatCVRF(json_data)
                # print(table_data)
                table_data.to_csv(
                    "csv/" + folder + "/output-" + line + ".csv",
                    index=False,
                    quotechar='"',
                    sep="\t",
                )
                # print(line)
            mergecsv(folder)
            csvToXlsx('CVE-all.csv', 'CVE-all.xlsx')
        else:
            print("parameter not met requirement")
