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

// Roadmap:
// * SSL Certificate Store Lookup (Windows)
// * Docker Deployment
// * MongoDB integration

tpl 1.15 module Traversys_SSL_getCert_Functions;

metadata
    __name:='Traversys getCert Functions';
    description:='Traversys getCert Functions';
    tree_path:='Traversys', 'SSL Discovery', 'getCert Functions';
end metadata;

definitions traversysGlobalDefs 1.6
    """
        Traversys Global Definitions.

        Change History:
        2013-10-03 1.0  WMF  :  Created.
        2017-02-28 1.1  WMF  :  Updated for XML parsing.
        2019-02-03 1.2  WMF  :  Added security cipher capture, artificial aging.
                                                Updated method of creating a unique key.
                                                Capturing subject and issuer details.
                                                Added multiple port handling.
        2019-04-17 1.3  WMF  :  Split to config and model patterns. Updated trigger to
                                Appliance SI (for consolidation scenario)
        2019-12-24 1.4 WMF   :  Reconfigured to license file.
        2020-04-05 1.5 WMF   :  Updated get key.
        2021-02-13 1.6 WMF   :  Removed licensing requirements for Open Source Edition.

        Snippits:
        host/address[@addr="192.168.1.75"]/../ports/port[@portid="443"]/script/table[@key="subject"]/elem[@key="countryName"]/text()

    """

    define validationCheck(h, i) -> xmlData, ips, getValid
    """
        License and validation check for getCert.

    """

        get:= discovery.fileInfo(h, "%i%/getcert");
        getValid:= false;
        secret:= '"_traversys"';
        ips:= [];
        xmlData:= none;

        capFile:= discovery.runCommand(h, '%i%/unlocker --xml');
        getValid:= true;

        if capFile and capFile.result then
            xdoc:=xpath.openDocument(regex.extract(capFile.result, regex "(?is)(<\?xml.*</nmaprun>)", raw "\1"));
            ips:=xpath.evaluate(xdoc,'//host/address/@addr');
            xpath.closeDocument(xdoc);
            xmlData:= regex.extract(capFile.result, regex "(?is)(<\?xml.*</nmaprun>)", raw "\1");
            getValid:= true;

        elif capFile and capFile.failure_reason = "NoAccessMethod" then
            log.warn("Validation Failure: Failed to decrypt capture file.");
            getValid:= false;

        else
            log.warn("Validation Failure: Capture file not found.");
            getValid:= false;

        end if;


        // Stamp all nodes created by our Pattern
        inferred:= search(PatternModule where name = 'Traversys_SSL_getCert_Triggers' or
                                              name = 'Traversys_SSL_getCert'
                            traverse PatternModule:PatternModuleContainment:Pattern:Pattern
                            traverse Pattern:Maintainer:Element:);

        for node in inferred do
            node._Traversys_getCert:= true;
        end for;

        return xmlData, ips, getValid;

    end define;

    define age(yes)
    """ Artificially age out nodes """

        if yes then
            old_details:= search(PatternModule where name = 'Traversys_SSL_getCert_Triggers'
                            traverse PatternModule:PatternModuleContainment:Pattern:Pattern
                            traverse Pattern:Maintainer:Element: where modified(#) < (currentTime() - 7*24*3600*10000000)
                            );
            for old_d in old_details do
                log.warn("Detail %old_d.name% not found in 7 days, removing...");
                model.destroy(old_d);
            end for;
        end if;

    end define;

    define existingNodes(key, ip_address, port) -> existing_ssl_nodes, ips, ports
        """
            Hosts can have multiple SSL certificates assigned to multiple IPs and Ports.
            The purpose of this function is to define query to look for an existing
            SSL certificate based on the composite key. If one is found, then the node
            will be updated and if the IP or port is new, this will be added.

            By default, this query looks for an existing certificate with a matching key.

            You can modify the query and key attribute as required.

        """

        existing_ssl_nodes:=search(Detail where key = "%key%");
        ips     := [ ip_address ];
        ports   := [ port ];

        if existing_ssl_nodes then
            ips     :=existing_ssl_nodes[0].all_ip_addresses;
            ports   :=existing_ssl_nodes[0].ports;
            if ip_address not in ips then
                list.append(ips, ip_address);
            end if;
            if port not in ports then
                list.append(ports, port);
            end if;
        end if;

        return existing_ssl_nodes, ips, ports;

    end define;

    define xtract(d,p) -> v
        """Supports XML single item list extraction"""

        v:="";

        l:=xpath.evaluate(d, p);
        if size(l) > 0 then
            v:=l[0];
        end if;

        return v;

    end define;

    define regex_shuffle(rx, var, rw) -> val
        "Parse multiple regex to get a value"

        val:="";
        for r in rx do
            val:= regex.extract(var, r, rw);
            if val then
                break;
            end if;
        end for;

        return val;

    end define;

    define add_it(n, ndt, attr, res, reg, rw)
        """Add additional attributes to Detail"""

        x:= regex.extract(res, reg, rw);
        if x then
            n[attr]:= x;
        elif ndt = n.source then
            n[attr]:= void;
        end if;

    end define;

    define att_cleanup()
        """Cleanup Inferred Attributes"""

        infer_nodes:= search(PatternModule where name = 'Traversys_SSL_getCert_Triggers'
                                              or name = 'Traversys_SSL_getCert'
                        traverse PatternModule:PatternModuleContainment:Pattern:Pattern
                        traverse Pattern:Maintainer:Element:
                       );
        inf_size:= size(infer_nodes);

        uniq_list:= search(in infer_nodes show keys(#) as "attr" processwith unique(0));
        uniq_size:= size(uniq_list);

        for node in uniq_list do
            attributes:= node[0];
            for attr in attributes do
                for det in infer_nodes do
                    if attr not in det then
                        continue;
                    elif det["%attr%"] = "" then
                        det[attr]:= void;
                    end if;
                end for;
            end for;
        end for;

    end define;

    define build_key(ip, subcn, isscn, t, ips, cns) -> k, n, cn
        "Get key for certificate"

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

        n:="%t% on %ip%";

        if cn matches "[A-Za-z0-9]" then
            n:="%t% for %cn% on %ip%";
        end if;

        k:=text.hash("%ip%/%cn%");
        log.debug("Key %k% created for %n%");

        return k, n, cn;

    end define;

    define unlink(yes, h, t)
        """ Unlink from a device """

        if yes then

            log.debug("Breaking relationship to %h.name%...");
            // Break relationship from the current Discovery appliance, orphan Details where no Host related.
            rs:=search(in h step in ElementWithDetail:Detail);
            for r in rs do
                ds:=search(in r step out Detail:Detail where type = "%t%");
                if ds then
                    log.debug("Unlinking %h.name% from %t%...");
                    model.destroy(r);
                end if;
            end for;

        end if;

    end define;

    define display_attrs(dt)
        "Add display attributes"
        l :=[ "issuer_name", "subject_name", "common_names", "valid_from", "valid_to", "template", "archived", "expired" ];
        if dt.port then
            list.append(l, "port");
        end if;
        if dt.serial_number then
            list.append(l, "serial_number");
        end if;
        model.addDisplayAttribute(dt, l);

    end define;

    define cleanse(dirty, q, u, k) -> clean
        "Cleanup attributes"

        // Strip Whitespace
        dirty:= text.strip(dirty);

        // Remove linebreaks
        dirty:= text.replace(dirty, "\n", "");
        dirty:= text.replace(dirty, "\r", "");

        // Remove all Quotes
        if q then
            dirty:= text.replace(dirty, '"', '');
            dirty:= text.replace(dirty, "'", "");
        end if;

        // Remove Sequential Underscores
        if u then
            dirty:= text.replace(dirty, regex.extract(dirty, regex "(__+\s?)", raw "\1"), "");
        end if;

        // Nuclear Option:
        // Remove all whitespaces and linebreaks, set UPPER
        if k then
            dirty:= text.upper(dirty);
            dirty:= text.replace(dirty, " ", "");
        end if;

        clean:= dirty;

        return clean;

    end define;

    define valid_dates(nb, na) -> vf, vt
        "Convert valid time formats"

        vf:= "No Data Available";
        vt:= "No Data Available";

        if nb matches "Can't parse" then
            log.warn("Valid From date parse error: %nb%");
        else
            nf:= time.parseUTC(nb);
            vf:= time.formatUTC(nf, "%%Y-%%m-%%d");
        end if;

        if na matches "Can't parse" then
            log.warn("Valid To date parse error: %na%");
        else
            nt:= time.parseUTC(na);
            vt:= time.formatUTC(nt, "%%Y-%%m-%%d");
        end if;

        return vf, vt;

    end define;

end definitions;
