import os
import xml.etree.ElementTree as ET
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv
from datetime import datetime
import hashlib

load_dotenv()

conn = psycopg2.connect(
    dbname=os.environ['POSTGRES_DB'],
    user=os.environ['POSTGRES_USER'],
    password=os.environ['POSTGRES_PASSWORD'],
    host=os.environ.get('POSTGRES_HOST', 'localhost'),
    port=os.environ.get('POSTGRES_PORT', 5432)
)
cursor = conn.cursor()

def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    certs = []

    for host in root.findall('host'):
        ip_elem = host.find('address[@addrtype="ipv4"]')
        ip = ip_elem.get('addr') if ip_elem is not None else None
        hostnames = [h.get('name') for h in host.findall('.//hostname')]
        hostname = hostnames[0] if hostnames else None
        ports = []

        for port in host.findall('.//port'):
            portid = port.get('portid')
            ports.append(portid)
            cert_script = port.find("script[@id='ssl-cert']")
            if cert_script is None:
                continue

            output = cert_script.get('output')
            sha1 = None
            md5 = None
            public_key_type = None
            public_key_bits = None
            subject = None
            issuer = None
            valid_from = None
            valid_to = None
            common_names = []
            subject_cn = subject_state = subject_country = subject_locality = subject_email = None
            issuer_cn = issuer_state = issuer_country = issuer_locality = issuer_email = None
            serial = None

            for elem in cert_script.findall('.//elem'):
                key = elem.get('key')
                val = elem.text
                if key == 'sha1':
                    sha1 = val
                elif key == 'md5':
                    md5 = val
                elif key == 'type':
                    public_key_type = val
                elif key == 'bits':
                    public_key_bits = int(val)
                elif key == 'sig_algo':
                    pass

            for table in cert_script.findall(".//table[@key='subject']"):
                for e in table.findall('elem'):
                    k = e.get('key')
                    v = e.text
                    if k == 'commonName': subject_cn = v; common_names.append(v)
                    elif k == 'stateOrProvinceName': subject_state = v
                    elif k == 'countryName': subject_country = v
                    elif k == 'localityName': subject_locality = v
                    elif k == 'emailAddress': subject_email = v
            for table in cert_script.findall(".//table[@key='issuer']"):
                for e in table.findall('elem'):
                    k = e.get('key')
                    v = e.text
                    if k == 'commonName': issuer_cn = v
                    elif k == 'stateOrProvinceName': issuer_state = v
                    elif k == 'countryName': issuer_country = v
                    elif k == 'localityName': issuer_locality = v
                    elif k == 'emailAddress': issuer_email = v

            for table in cert_script.findall(".//table[@key='validity']"):
                for e in table.findall('elem'):
                    if e.get('key') == 'notBefore':
                        raw_not_before = e.text
                        valid_from = datetime.fromisoformat(e.text)
                    elif e.get('key') == 'notAfter':
                        raw_not_after = e.text
                        valid_to = datetime.fromisoformat(e.text)

            serial = hashlib.sha1((ip + (sha1 or '')).encode()).hexdigest()
            key_id = serial

            certs.append((
                key_id, hostname, 'ssl', valid_from, valid_to, ','.join(common_names),
                public_key_type == 'rsa', sha1, subject, issuer, ','.join(ports), ip,
                f'{ip}:{portid}', serial, None, None, None, subject_cn, subject_state,
                subject_country, subject_locality, subject_email, issuer_cn, issuer_state,
                issuer_country, issuer_locality, issuer_email, output, raw_not_before,
                raw_not_after, md5, public_key_type, public_key_bits, None
            ))

    return certs

    insert_sql = '''
        INSERT INTO certificates VALUES %s
        ON CONFLICT (key) DO UPDATE SET
            name = EXCLUDED.name,
            valid_from = EXCLUDED.valid_from,
            valid_to = EXCLUDED.valid_to,
            sha_1_fingerprint = EXCLUDED.sha_1_fingerprint,
            md5sum = EXCLUDED.md5sum,
            raw_output = EXCLUDED.raw_output
    '''
    execute_values(cursor, insert_sql, cert_data)
    conn.commit()

if __name__ == '__main__':
    xml_file = 'output.xml'
    cert_data = parse_nmap_xml(xml_file)
    upsert_cert_data(cert_data)
    cursor.close()
    conn.close()
