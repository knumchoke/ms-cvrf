# Readme

## Requirement

```bash
  $ pip3 install -r 
```

## Usage

```bash
  $ python3 get-cvrf.py <mode> <CVE_NO|cvetextfile> <folder>
```

## Explaination

### Modes

- `download` will download json CVE data.
- `read` will convert json from `download` mode to csv.
- `batch` will run `download` and `read` using cve number listed in text file. Then merging to `CVE-all.csv` and convert to `CVE-all.xlsx`

### Parameters

- `<CVE_NO>` is CVE number in format CVE-yyyy-nnnnn.
- `<cvetextfile>` is text file contain list of CVEs, line by line, see example in `cvelist.txt`.
- `<folder>` is folder that this script will write the file to, upto the running mode, `download` will write to json, `read` will write to csv, `batch` will write to both folder.
