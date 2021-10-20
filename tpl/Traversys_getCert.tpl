// (c) Copyright 2015-2021, Traversys Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

tpl 1.18 module Traversys_SSL_getCert;

metadata
    origin:= "Traversys Limited";
    __name          :='Traversys getCert';
    description     :='Traversys getCert';
    tree_path       :='Traversys', 'getCert', 'getCert';
    extra_rel_kinds := "Detail:Detail:ElementWithDetail:StorageDevice","Detail:Detail:ElementWithDetail:SNMPManagedDevice","Detail:Detail:ElementWithDetail:Printer";
end metadata;

from traversys_getCert_funcs import getcert 1.7;

pattern traversys_getCert 1.5
    '''
    Traversys getCert Main Body

    (c) Copyright 2015-2020, Traversys Limited

    Change History:
    2017-10-03 1.0  WMF  :  Created.
    2019-02-03 1.1  WMF  :  Added security cipher capture, artificial aging.
                            Updated method of creating a unique key.
                            Capturing subject and issuer details.
                            Added multiple port handling.
    2019-12-29 1.2  WMF  :  Free Edition release.
    2020-04-13 1.3  WMF  :  Added removal groups, new method to capture serial
                            number and other details.
    2021-02-13 1.4 WMF   :  Removed licensing requirements for Open Source Edition.
    2021-10-12 1.5 WMF   :  Updated attributes to match BMC TKU certificate details.
                            Migrated to SofwareInstance link. Will generate new SI
                            if missing.
                            Main pattern now triggers on ExternalEvent.

    You may copy and modify this to generate your own SSL Certificate model.

    '''

    overview
        tags ssl, getCert, traversys;
    end overview;

    constants
        type:="SSL Certificate";
    end constants;

    triggers
        on event := ExternalEvent created where type = "cert_scan";
    end triggers;

    body

        getCert_host := discovery.dataSource("getCert");
        gpg_file     := event.file;
        phrase       := event.phrase;

        //test:= discovery.runCommand(getCert_host, 'whoami && pwd');
        get:= discovery.fileInfo(getCert_host, "%gpg_file%");

        if get and get.method_success then
            decrypt:= discovery.runCommand(getCert_host, 'echo "%phrase%" | gpg -d --batch --yes --quiet --no-mdc-warning --passphrase-fd 0 --decrypt %gpg_file%');
            if decrypt and decrypt.result then
                xdoc:=xpath.openDocument(regex.extract(decrypt.result, regex "(?is)(<\?xml.*</nmaprun>)", raw "\1"));
                ips:=xpath.evaluate(xdoc,'//host/address/@addr');
                xpath.closeDocument(xdoc);
                xmlData:= regex.extract(decrypt.result, regex "(?is)(<\?xml.*</nmaprun>)", raw "\1");
            elif decrypt and decrypt.failure_reason = "NoAccessMethod" then
                log.critical("Failure: Failed to decrypt %gpg_file%.");
                stop;
            else
                log.critical("Failure: Issue with %gpg_file%.");
                stop;
            end if;
        else
            log.critical("Failure: %gpg_file% not found.");
            stop;
        end if;

        ip_addrs:=xpath.evaluate(xdoc,'//host/address/@addr');

        for ip_addr in ip_addrs do

            ports:=xpath.evaluate(xdoc,'//host/address[@addr="%ip_addr%"]/../ports/port/@portid');

            for port in ports do

                root_xml:='//host/address[@addr="%ip_addr%"]/../ports/port[@portid="%port%"]';

                portstate:=getcert.xValue(xdoc,root_xml+'/state/@state');
                if portstate = "closed" then
                    log.warn("%ip_addr%:%port% closed, skipping...");
                    continue;
                end if;

                rawout:=getcert.xValue(xdoc,root_xml+'/script/@output');
                if not rawout then
                    log.warn("No SSL Certificate found on port %port%, skipping...");
                    continue;
                end if;

                sub_cname      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="commonName"]/text()');
                sub_cname      := text.lower(sub_cname);
                sub_country    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="countryName"]/text()');
                sub_state      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="stateOrProvinceName"]/text()');
                sub_locality   :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="localityName"]/text()');
                sub_orgname    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="organizationName"]/text()');
                sub_email      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="emailAddress"]/text()');
                sub_orgunit    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="organizationalUnitName"]/text()');

                sub:= "commonName=%sub_cname%; countryName=%sub_country%; stateOrProvinceName=%sub_state%; localityName=%sub_locality%; organizationName=%sub_orgname%; organizationalUnitName=%sub_orgunit%; emailAddress=%sub_email%;";

                iss_cname      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="commonName"]/text()');
                iss_cname      := text.lower(iss_cname);
                iss_country    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="countryName"]/text()');
                iss_state      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="stateOrProvinceName"]/text()');
                iss_locality   :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="localityName"]/text()');
                iss_orgname    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="organizationName"]/text()');
                iss_email      :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="emailAddress"]/text()');
                iss_orgunit    :=getcert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="organizationalUnitName"]/text()');

                iss:= "commonName=%iss_cname%; countryName=%iss_country%; stateOrProvinceName=%iss_state%; localityName=%iss_locality%; organizationName=%iss_orgname%; organizationalUnitName=%iss_orgunit%; emailAddress=%iss_email%;";

                sha1:=getcert.xValue(xdoc,root_xml+'/script/elem[@key="sha1"]/text()');
                pubkeytype:=getcert.xValue(xdoc,root_xml+'/script/table[@key="pubkey"]/elem[@key="type"]/text()');
                pubkeybits:=getcert.xValue(xdoc,root_xml+'/script/table[@key="pubkey"]/elem[@key="bits"]/text()');
                subaltname:=getcert.xValue(xdoc,root_xml+'/script/table[@key="extensions"]/table[elem/text()="X509v3 Subject Alternative Name"]/elem[@key="value"]/text()');
                notbefore:=getcert.xValue(xdoc,root_xml+'/script/table/elem[@key="notBefore"]/text()');
                date:= regex.extract(notbefore, regex "((\d+-?)+)T", raw "\1");
                dtime:= regex.extract(notbefore, regex "T((\d+:?)+)", raw "\1");
                validfrom:="%date% %dtime%";
                notafter:=getcert.xValue(xdoc,root_xml+'/script/table/elem[@key="notAfter"]/text()');
                date:= regex.extract(notafter, regex "((\d+-?)+)T", raw "\1");
                dtime:= regex.extract(notafter, regex "T((\d+:?)+)", raw "\1");
                validto:="%date% %dtime%";
                md5:=getcert.xValue(xdoc,root_xml+'/script/elem[@key="md5"]/text()');
                re:="%pubkeybits%-bit";

                // This function cleans up the date values
                valid_from, valid_to:= getcert.valid_dates(validfrom, validto);

                dev_ips:= search(DiscoveryAccess where _last_marker and endpoint = "%ip_addr%" traverse Associate:Inference:InferredElement:);
                dev_cns:=search(Host,NetworkDevice,StorageSystem,SNMPManagedDevice,Printer where local_fqdn = "%sub_cname%"
                                    or hostname = "%sub_cname%"
                                    or name = "%sub_cname%"
                                    or sysname = "%sub_cname%"
                                    or local_fqdn = "%iss_cname%"
                                    or hostname = "%iss_cname%"
                                    or name = "%iss_cname%"
                                    or sysname = "%iss_cname%");

                // This function will automatically generate a unique key and name values
                key, name, common_names:=getcert.build_key(ip_addr, sub_cname, iss_cname, type, dev_ips, dev_cns);

                ips        := [ ip_addr ];
                ports      := [ port ];
                connection := "%ip_addr%:%port%";
                connections:= [ connection ];

                // Additional Info
                serial:= none;
                errors:= none;
                sha256:= none;
                self_signed:= false;

                scan:= discovery.runCommand(getCert_host, "timeout 1 openssl s_client -connect %connection% | openssl x509 -noout -fingerprint -sha256 -serial");

                if scan and scan.result then
                    serial:=regex.extract(scan.result, regex "serial=(\w+)", raw "\1");
                    errors:=regex.extract(scan.result, regex "verify error:(.*)", raw "\1");
                    sha256:=regex.extract(scan.result, regex 'SHA256 Fingerprint=(\S+)', raw '\1');
                    if errors and errors matches "self signed certificate" then
                        self_signed:= true;
                    end if;
                    if sha256 then
                        key:= "%ip_addr%/Cert/%sha256%"; // Matches BMC TKU
                    end if;
                end if;

                // Get Ciphers
                ciphers:=getcert.xValue(xdoc,root_xml+'/script[2]/@output');

                // Get Warnings
                warnings:=getcert.xValue(xdoc,root_xml+'/script[2]/table/table[@key="warnings"]/elem/text()');

                // Get Certificate Strength
                least_strength:=getcert.xValue(xdoc,root_xml+'/script[2]/elem[@key="least strength"]/text()');

                existing_ssl_nodes:=search(Detail where key = "%key%");

                if existing_ssl_nodes then
                    ips        :=existing_ssl_nodes[0].all_ip_addresses;
                    ports      :=existing_ssl_nodes[0].ports;
                    connections:=existing_ssl_nodes[0].connections;
                    if ip_addr not in ips then
                        list.append(ips, ip_addr);
                    end if;
                    if port not in ports then
                        list.append(ports, port);
                    end if;
                    if connection not in connections then
                        list.append(connections, connection);
                    end if;
                end if;

                //Model SSL Certificate as Detail

                cd := model.Detail(
                                     key                        := key,
                                     name                       := name,
                                     type                       := type,
                                     valid_from                 := valid_from,
                                     valid_to                   := valid_to,
                                     start_date                 := valid_from, // BMC TKU Value
                                     expiry_date                := valid_to, // BMC TKU Value
                                     common_names               := common_names,
                                     common_name                := sub_cname, // BMC TKU Value
                                     short_name                 := sub_cname, // BMC TKU Value
                                     rsa_encryption             := re,
                                     sha_1_fingerprint          := sha1,
                                     sha_256_fingerprint        := sha256, // BMC TKU Value - SHA256, can only be retrieved with OpenSSL
                                     subject                    := sub,
                                     issuer                     := iss,
                                     organization               := sub_orgname, // BMC TKU Value
                                     organization_unit          := sub_orgunit, // BMC TKU Value
                                     subject_alternative_name   := subaltname, // BMC TKU Value
                                     ports                      := ports,
                                     all_ip_addresses           := ips,
                                     connections                := connections,
                                     serial                     := serial,
                                     warnings                   := warnings,
                                     errors                     := errors,
                                     least_strength             := least_strength,
                                     _subject_cn                := sub_cname,
                                     _subject_organization_name := sub_orgname,
                                     _subject_state             := sub_state,
                                     _sujbect_country           := sub_country,
                                     _subject_locality          := sub_locality,
                                     _subject_email             := sub_email,
                                     _subject_organization_unit := sub_orgunit,
                                     _issuer_cn                 := iss_cname,
                                     _issuer_organization_name  := iss_orgname,
                                     _issuer_state              := iss_state,
                                     _issuer_country            := iss_country,
                                     _issuer_locality           := iss_locality,
                                     _issuer_email              := iss_email,
                                     _issuer_organization_unit  := iss_orgunit,
                                     _raw_output                := rawout,
                                     _raw_not_before            := notbefore,
                                     _raw_not_after             := notafter,
                                     _md5sum                    := md5,
                                     _public_key_type           := pubkeytype,
                                     _public_key_bits           := pubkeybits,
                                     _ciphers                   := ciphers
                                 );

                log.info("Created Detail node for %cd.name%");
                model.setRemovalGroup(cd, "ssl_details");

                if self_signed then
                    cd.self_signed:= self_signed;
                end if;

                // Attempt to map to SoftwareInstances
                devices := [];
                for dev in dev_ips do
                    list.append(devices,dev);
                end for;

                for dev in dev_cns do
                    list.append(devices,dev);
                end for;

                sis_with_ports:= [];
                for port in ports do
                    portn:= text.toNumber(port);
                    // Lookup SIs direct - quick win
                    log.debug("Looking for SIs with Port %port%...");
                    dev_sis:= search(in devices traverse Host:HostedSoftware::SoftwareInstance where port = %portn%);
                    si_count:= size(dev_sis);
                    log.debug("Device SIs found %si_count%");
                    can_sis:= search(in devices traverse Host:HostedSoftware:RunningSoftware:CandidateSoftwareInstance where port = %portn%);
                    if size(dev_sis) > 0 or size(can_sis) > 0 then
                        log.debug("Found SIs with Port %port%");
                        for si in dev_sis do
                            log.debug("SI: %si.name%");
                            list.append(sis_with_ports,si);
                        end for;
                        for si in can_sis do
                            log.debug("Candidate SI: %si.name%");
                            list.append(sis_with_ports,si);
                        end for;
                    else
                        // Get process from inferred nodes
                        log.debug("Looking for listening port %port%");
                        related_ports:= search(in devices
                                                traverse InferredElement:Inference:Associate:DiscoveryAccess
                                                    traverse DiscoveryAccess:DiscoveryAccessResult:DiscoveryResult:NetworkConnectionList
                                                        traverse List:List:Member:DiscoveredListeningPort);
                        for rel_port in related_ports do
                            log.debug("Checking port %rel_port.local_port%");
                            if portn = rel_port.local_port then
                                log.debug("Listening port %port% found");
                                related_procs:= search(in rel_port processwith processesForCommunication());
                                for rel_proc in related_procs do
                                    log.debug("Looking for related SIs on %port%");
                                    related_sis:= search(in rel_proc traverse :Inference:InferredElement:SoftwareInstance);
                                    related_csis:= search(in rel_proc traverse Associate:Inference:InferredElement:CandidateSoftwareInstance);
                                    if size(related_sis) > 0 or size(related_csis) > 0 then
                                        log.debug("Found related SIs on %port%");
                                        for si in related_sis do
                                            list.append(sis_with_ports,si);
                                        end for;
                                        for si in related_csis do
                                            list.append(sis_with_ports,si);
                                        end for;
                                    else
                                        log.debug("No related SIs for %port%, generating new SI...");
                                        newType:= regex.extract(rel_proc.cmd, regex "\b(\S+(\.exe))?$", raw "\1");
                                        da:= discovery.access(rel_proc);
                                        host:= related.host(da);
                                        newSI := model.SoftwareInstance(key:= key,
                                                                        type:= newType,
                                                                        name:= "%newType% on %host.name%",
                                                                        port:= portn
                                                                        );
                                        log.info("New SI created %newSI.name%...");
                                        model.setRemovalGroup(cd, "ssl_details");
                                        model.rel.HostedSoftware(Host := host, RunningSoftware := newSI);
                                        list.append(sis_with_ports,newSI);
                                    end if;
                                end for;
                            end if;
                        end for;
                    end if;

                    if size(sis_with_ports) > 0 then
                        log.debug("Linking certificate to SI...");
                        for si in dev_sis do
                            log.debug("%si.name%");
                            model.rel.Detail(ElementWithDetail := si, Detail := cd);
                        end for;
                    else
                        for device in devices do
                            log.debug("No related nodes for %port%");
                            if model.kind(device) = "Host" then
                                log.info("Generating new SI for cert %cd.name%...");
                                newType:= sub_cname;
                                host:= device;
                                newSI := model.SoftwareInstance(key:= key,
                                                                type:= newType,
                                                                name:= "%newType% on %host.name%",
                                                                port:= portn
                                                                );
                                log.info("New SI created %newSI.name%...");
                                model.rel.Detail(ElementWithDetail := newSI, Detail := cd);
                                model.rel.HostedSoftware(Host := device, RunningSoftware := newSI);
                            else // Attach to the device itself
                                log.info("Association Cert %cd.name% with device %device.name%...");
                                // snmp, printer and storage devices don't have a direct relationship to Detail
                                // new relationships added in metadata
                                dt:=model.rel.Detail(ElementWithDetail:=device, Detail:=cd);
                            end if;
                        end for;
                    end if;

                end for;

            end for;

        end for;

        xpath.closeDocument(xdoc);

        // Attribute cleanup - Inferred nodes only
        getcert.att_cleanup();

    end body;

end pattern;
