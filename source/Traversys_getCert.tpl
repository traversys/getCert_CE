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

tpl 1.15 module Traversys_SSL_getCert;

metadata
    __name:='Traversys getCert';
    description:='Traversys getCert Main Pattern';
    tree_path:='Traversys', 'SSL Discovery', 'getCert';
end metadata;

//// Remove Import lines to make changes ////
from Traversys_SSL_getCert_Functions import traversysGlobalDefs 1.6;
from Traversys_SSL_getCert_Config import traversysConfig 1.2, Traversys_getCert_Config 1.0;
/////////////////////////////////////////////

definitions traversysGetCert 1.3
    """
        Traversys SSL Certificate Disovery specific definitions.
    """

    define xValue(xKey, path) -> value
        """ Supports XML single item list extraction """

        value:="";

        len:=xpath.evaluate(xKey, path);
        if size(len) > 0 then
            value:=len[0];
        end if;

        return value;

    end define;

    define build_key(ip, subcn, isscn, type, ips, cns) -> key, name, cn
        """ Generate a key for certificate """

        cn:= "%subcn%/%isscn%";

        if not subcn matches "[A-Za-z0-9]" then
            cn:= isscn;
        end if;

        if not isscn matches "[A-Za-z0-9]" then
            cn:= subcn;
        end if;

        if size(ips) > 0 then
            ip:= ips[0].name;
        elif size(cns) > 0 then
            ip:= cns[0].name;
        end if;

        name:="%type% on %ip%";

        if cn matches "[A-Za-z0-9]" then
            name:="%type% for %cn% on %ip%";
        end if;

        key:=text.hash("%ip%/%cn%");
        log.debug("Key %key% created for %name%");

        return key, name, cn;

    end define;

end definitions;


pattern Traversys_getCert 1.4
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

    You may copy and modify this to generate your own SSL Certificate model.

    Once changes are uploaded, you will need to reinstall getCert to revert to
    original.

    '''

    overview
        tags ssl, getCert, traversys;
    end overview;

    constants
        type:="SSL Certificate Detail";
    end constants;

    triggers
        on f:=File created, confirmed where name = "getCert XML";
    end triggers;

    body

        host:= none;

        si:= search(in f traverse File:RelatedFile:ElementUsingFile:SoftwareInstance);
        if size(si) > 0 then
            host:= related.host(si[0]);
        else
            sis:= search(SoftwareInstance where key = "%f.key%");
            if size(sis) > 0 then
                host:= related.host(sis[0]);
            end if;
        end if;

        xdoc:=xpath.openDocument(f.content);

        ip_addrs:=xpath.evaluate(xdoc,'//host/address/@addr');

        for ip_addr in ip_addrs do

            ports:=xpath.evaluate(xdoc,'//host/address[@addr="%ip_addr%"]/../ports/port/@portid');

            for port in ports do

                root_xml:='//host/address[@addr="%ip_addr%"]/../ports/port[@portid="%port%"]';

                portstate:=traversysGetCert.xValue(xdoc,root_xml+'/state/@state');
                if portstate = "closed" then
                    log.warn("%ip_addr%:%port% closed, skipping...");
                    continue;
                end if;

                rawout:=traversysGetCert.xValue(xdoc,root_xml+'/script/@output');
                if not rawout then
                    log.warn("No SSL Certificate found on port %port%, skipping...");
                    continue;
                end if;

                sub_cname      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="commonName"]/text()');
                sub_cname      := text.lower(sub_cname);
                sub_country    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="countryName"]/text()');
                sub_state      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="stateOrProvinceName"]/text()');
                sub_locality   :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="localityName"]/text()');
                sub_orgname    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="organizationName"]/text()');
                sub_email      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="emailAddress"]/text()');
                sub_orgunit    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="subject"]/elem[@key="organizationalUnitName"]/text()');

                sub:= "commonName=%sub_cname%; countryName=%sub_country%; stateOrProvinceName=%sub_state%; localityName=%sub_locality%; organizationName=%sub_orgname%; organizationalUnitName=%sub_orgunit%; emailAddress=%sub_email%;";

                iss_cname      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="commonName"]/text()');
                iss_cname      := text.lower(iss_cname);
                iss_country    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="countryName"]/text()');
                iss_state      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="stateOrProvinceName"]/text()');
                iss_locality   :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="localityName"]/text()');
                iss_orgname    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="organizationName"]/text()');
                iss_email      :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="emailAddress"]/text()');
                iss_orgunit    :=traversysGetCert.xValue(xdoc,root_xml+'/script/table[@key="issuer"]/elem[@key="organizationalUnitName"]/text()');

                iss:= "commonName=%iss_cname%; countryName=%iss_country%; stateOrProvinceName=%iss_state%; localityName=%iss_locality%; organizationName=%iss_orgname%; organizationalUnitName=%iss_orgunit%; emailAddress=%iss_email%;";

                sha:=traversysGetCert.xValue(xdoc,root_xml+'/script/[@key="sha1"]/text()');
                pubkeytype:=traversysGetCert.xValue(xdoc,root_xml+'/script/table/elem[@key="type"]/text()');
                pubkeybits:=traversysGetCert.xValue(xdoc,root_xml+'/script/table/elem[@key="bits"]/text()');
                notbefore:=traversysGetCert.xValue(xdoc,root_xml+'/script/table/elem[@key="notBefore"]/text()');
                date:= regex.extract(notbefore, regex "((\d+-?)+)T", raw "\1");
                dtime:= regex.extract(notbefore, regex "T((\d+:?)+)", raw "\1");
                validfrom:="%date% %dtime%";
                notafter:=traversysGetCert.xValue(xdoc,root_xml+'/script/table/elem[@key="notAfter"]/text()');
                date:= regex.extract(notafter, regex "((\d+-?)+)T", raw "\1");
                dtime:= regex.extract(notafter, regex "T((\d+:?)+)", raw "\1");
                validto:="%date% %dtime%";
                md5:=traversysGetCert.xValue(xdoc,root_xml+'/script/elem[@key="md5"]/text()');
                re:="%pubkeybits%-bit";

                // This function cleans up the date values
                valid_from, valid_to:= traversysGlobalDefs.valid_dates(validfrom, validto);

                dev_ips:= search(DiscoveryAccess where _last_marker and endpoint = "%ip_addr%" traverse Associate:Inference:InferredElement:);
                dev_cns:=search( * where local_fqdn = "%sub_cname%" or hostname = "%sub_cname%" or local_fqdn = "%iss_cname%" or hostname = "%iss_cname%");

                // This function will automatically generate a unique key and name values
                key, name, common_names:=traversysGetCert.build_key(ip_addr, sub_cname, iss_cname, type, dev_ips, dev_cns);

                ips        := [ ip_addr ];
                ports      := [ port ];
                connection := "%ip_addr%:%port%";
                connections:= [ connection ];

                // Additional Info
                serial:= none;
                errors:= none;
                self_signed:= none;

                scan_cmd:= "%traversysConfig.install_dir%/unlocker --ssl ";

                if host then
                    scan:= discovery.runCommand(host, scan_cmd+connection);

                    if scan and scan.result then
                        serial:=regex.extract(scan.result, regex "serial=(\w+)", raw "\1");
                        errors:=regex.extract(scan.result, regex "verify error:(.*)", raw "\1");
                        if errors and errors matches "self signed certificate" then
                            self_signed:= true;
                        end if;
                    end if;
                end if;

                // Get Ciphers
                ciphers:=traversysGetCert.xValue(xdoc,root_xml+'/script[2]/@output');

                // Get Warnings
                warnings:=traversysGetCert.xValue(xdoc,root_xml+'/script[2]/table/table[@key="warnings"]/elem/text()');

                // Get Certificate Strength
                least_strength:=traversysGetCert.xValue(xdoc,root_xml+'/script[2]/elem[@key="least strength"]/text()');

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
                                     common_names               := common_names,
                                     rsa_encryption             := re,
                                     subject                    := sub,
                                     issuer                     := iss,
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
                                     _sha                       := sha,
                                     _public_key_type           := pubkeytype,
                                     _public_key_bits           := pubkeybits,
                                     _ciphers                   := ciphers
                                 );

                log.info("Created Detail node for %cd.name%");
                if traversysConfig.rem_group then
                    model.setRemovalGroup(cd, "ssl_details");
                end if;

                if self_signed then
                    cd.self_signed:= self_signed;
                end if;

                if traversysConfig.map_device then
                    // Search for a host with the IP, if it exists, map the detail to the host
                    for dev in dev_ips do
                        dt:=model.rel.Detail(ElementWithDetail:=dev, Detail:=cd);
                    end for;
                end if;

                if traversysConfig.map_name then
                    // Search for a host common name
                    for dev in dev_cns do
                        dt:=model.rel.Detail(ElementWithDetail:=dev, Detail:=cd);
                    end for;
                end if;

            end for;

        end for;

        xpath.closeDocument(xdoc);

        // Optional break relationship from the current Discovery appliance -
        // results in orphan Details where no Device is related
        traversysGlobalDefs.unlink(traversysConfig.break_relationship, host, type);

    end body;

end pattern;
