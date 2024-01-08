import sys
import requests

def get_ms_kb_links(cve):
    # url = f'https://api.msrc.microsoft.com/cvrf/{cve}'
    url = f'https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=cveNumber%20eq%20%27CVE-2022-37967%27'
    response = requests.get(url)
    data = response.json()

    products = []
    kb_links = []

    for vuln in data['Vulnerability']:
        for prod in vuln['ProductStatus']:
            if prod['Status'] == 'Affected':
                products.append(prod['ProductName'][0]['Value'])
                for ref in vuln['References']:
                    if 'https://support.microsoft.com/en-us/help' in ref['URL']:
                        kb_links.append(ref['URL'])

    return products, kb_links

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python get_ms_kb_links.py <CVE-Number>')
    else:
        cve = sys.argv[1]
        products, kb_links = get_ms_kb_links(cve)
        print('Affected products:', products)
        print('KB links:', kb_links)