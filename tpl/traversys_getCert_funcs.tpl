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

tpl 1.15 module traversys_getCert_funcs;

metadata
    origin:= "Traversys Limited";
    __name:='Traversys getCert Functions';
    description:='Traversys getCert Functions';
    tree_path:='Traversys', 'getCert', 'Functions';
end metadata;

definitions getcert 1.7
    """
        Traversys Global Definitions.

        Change History:
        2013-10-03 1.0 WMF : Created.
        2017-02-28 1.1 WMF : Updated for XML parsing.
        2019-02-03 1.2 WMF : Added security cipher capture, artificial aging.
                                Updated method of creating a unique key.
                                Capturing subject and issuer details.
                                Added multiple port handling.
        2019-04-17 1.3 WMF : Split to config and model patterns. Updated trigger to
                                Appliance SI (for consolidation scenario)
        2019-12-24 1.4 WMF : Reconfigured to license file.
        2020-04-05 1.5 WMF : Updated get key.
        2021-02-13 1.6 WMF : Removed licensing requirements for Open Source Edition.
        2021-10-14 1.7 WMF : Refactored for newer pattern config.

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

    define att_cleanup()
        """Cleanup Inferred Attributes"""

        infer_nodes:= search(PatternModule where name = 'Traversys_SSL_getCert'
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

end definitions;
