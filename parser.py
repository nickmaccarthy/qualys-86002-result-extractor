import csv
import os
import sys
import re
import getopt
import collections

''' Parses relevant SSL information from a Qualys report for QID 86002 and creates a new CSV file with certificate details '''

csv.field_size_limit(sys.maxsize)

CV_HOME = os.path.abspath(os.path.join(os.path.dirname(__file__)))

'''Return first item in sequence where our item is in the list'''
def find(f, seq):
  for item in seq:
    if f in item:
        return item

''' Gets the Subject Common Name from the results
    This is typically the domain name the certificate is issued for '''
def get_subject_common_name(results):
    regex = re.compile(".*\(0\)SUBJECT NAME.*?commonName\s+(.*?)$",re.MULTILINE|re.DOTALL)
    r = regex.match(results)
    if r:
        return r.group(1).strip()
    else:
        return "Not found"

''' Gets the issuer name for the certificate '''
def get_issuer_name(results):
    m = re.search('.*\(\d+\)ISSUER NAME.*?\s*organizationName\s+(.*?)$', results, re.M|re.DOTALL)
    if m:
        res = m.group(1).strip()
        res = res.replace('"', '')
        return res
    else:
        return "Not found"

def regexit(regex, string):
    reg = re.compile(regex)
    m = re.search(reg, string)
    if m:
        return m.group(1).strip()
    else:
        return "Not found"

def clean(text):
    text = str(text)
    escape_these = ',()'

    for char in escape_these:
        text = text.replace(char, '')
    return text

''' read inputs from CLI '''    
def readinputs(argv):
    try:
        optlist, args = getopt.getopt(argv, '', ['infile=', 'outfile='])
    except getopt.GetoptError, e:
        usage(e)
        sys.exit(2)

    if len(optlist) < 2:
        usage()
        sys.exit(2)
    
    returnDict = {}
    for name, value in optlist:
       returnDict[name[2:]] = value.strip()

    return returnDict

def usage():
   def usage():
    print "\n"
    help_def()
    print "\n\n"
    
    print "Usage:"
    print "python parser.py --infile=/location/of/source/file.csv --outfile=/location/of/where/you/want/results.csv" 
    print "example: python parser.py --infile=c:/86002_results.csv --outfile=c:/parsed_results.csv"
    print "\n"

def help_def():
    print "Parses a QID 86002 report and extracts SSL certificate information from the Qualys results"
    #print "Outputs a file in %s called 'kb.csv'" % CV_HOME 

def main(argv):

    opts = readinputs(argv)

    if not opts['infile'] and not opts['outfile']:
        usage()
    with open(opts['infile'], 'r') as fh:
        lines = fh.readlines()

        try:
            start_idx = lines.index('"IP","Network","DNS","NetBIOS","Tracking Method","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS Environment","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Ticket State","Instance","OS CPE","Category"\r\n')
        except:
            start_idx = lines.index('"IP","DNS","NetBIOS","Tracking Method","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS Environment","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Ticket State","Instance","OS CPE","Category"\r\n')
        finally:
            print "Im unable to detect where the results section of the file starts.  Ensure you have run the correct report in Qualys"
            sys.exit()


        qualys_csv = lines[start_idx:]

        fields = [ "IP","Network","DNS","NetBIOS","Tracking Method","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS Environment","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Ticket State","Instance","OS CPE","Category" ]
        reader = csv.DictReader(qualys_csv,  dialect='excel')

        sigalg = "Not found"
        validfrom = "Not found"
        validtill = "Not found"
        commonname = "Not found"
        pubkey_strength = "Not found"
        serialnubmer = "Not found"

        datal = []
        for row in reader:
            if row['Results'] is not None:
                print "Working on IP: {0}".format(row['IP'])

                certs = re.split('\(\d+\)CERTIFICATE \d+', row['Results'])
                certs = certs[1:]
                for cert in certs:
                    results = cert.splitlines()

                    sigalg_match = find('Signature Algorithm', results)
                    if sigalg_match:
                        sigalg = regexit("\(\d+\)Signature Algorithm\s+(.*?)$", sigalg_match)

                    validfrom_match = find('Valid From', results)
                    if validfrom_match:
                        validfrom = regexit("\(\d+\)Valid From\s+(.*?)$", validfrom_match)

                    validtill_match = find('Valid Till', results)
                    if validtill_match:
                        validtill = regexit("\(\d+\)Valid Till\s+(.*?)$", validtill_match)

                    commonname_match = find('commonName', results)
                    if commonname_match:
                        commonname = regexit('commonName\s+(.*?)$', commonname_match)

                    pubkey_strength_match = find('RSA Public Key', results)
                    if pubkey_strength_match:
                        pubkey_strength = regexit('RSA Public Key\s+\((.*?)\)$', pubkey_strength_match)

                    serial_number_match = find('Serial Number', results)
                    if serial_number_match:
                        serialnumber = regexit('\(\d+\)Serial Number\s+(.*?)$', serial_number_match)

                    issuer_name = get_issuer_name(cert)
                    subject_common_name = get_subject_common_name(cert)

                    ''' If you want more information from the source report, simply add it to this OrderedDict '''
                    d = collections.OrderedDict()
                    d["IP"] = row['IP']
                    d["DNS"] = row['DNS']
                    d["FQDN"] = row['FQDN']
                    d["IssuerName"] = issuer_name
                    d["SubjectCommonName"] = subject_common_name
                    d["SignatureAlgorithm"] = sigalg
                    d["SerialNumber"] = serialnumber
                    d["PubKey_Strength"] =  pubkey_strength
                    d["Valid_From"] =  validfrom
                    d["Valid_Till"]  = validtill

                    datal.append(d)

    headers = datal[0].keys()

    with open(opts['outfile'], 'wb') as wh:
        dw = csv.DictWriter(wh, delimiter=',', quotechar='"', dialect='excel', fieldnames=headers)
        dw.writeheader()
        for l in datal:
            dw.writerow(l)


    print "All done - you can find your formatted results at: {0}".format(opts['outfile'])


if __name__ == "__main__":
    main(sys.argv[1:])
