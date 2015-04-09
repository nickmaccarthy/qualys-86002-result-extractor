## Qualys QID 86002 SSL Results Extractor ##

#### Extracts SSL information from the results of QID 86002 from a Qualys Patch Report ####
-------------------------------------------
#### Requirements ####
Python 2.7

#### Usage ####
-------------------------------------------

* Ensure you have Python 2.7 installed.  This comes default on Mac's, and for Windows, an MSI installer can simply be downloaded from Python's website: https://www.python.org/downloads/release/python-279/
* Download the zip file on the right site, or git clone this branch
* In Qualys, run a report to .csv looking for only 86002 across all your assets utilizing the static search lists feature.  The report only needs to include the results section for display.
* Remember where you downloaded the Qualys CSV report to or put it in the folder where you unzipped this python script to in step 2
* Fire up CLI and point it to where location where you unzipped or cloned this branch
* Run the commands below 

`python parser.py --infile=/location/of/source/file.csv --outfile=cert_results.csv`

example ( assuming 86002 csv report is in the same directory as the python script ): 

`python parser.py --infile=86002_results.csv --outfile=parsed_results.csv`
