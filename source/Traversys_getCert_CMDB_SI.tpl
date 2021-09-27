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

tpl 1.15 module Traversys_SSL_getCert_CMDB_SI;

metadata
    origin:= "Traversys Limited";
    __name:='Traversys getCert';
    description:='Traversys getCert CMDB sync pattern';
    tree_path:='Traversys', 'SSL Discovery', 'getCert CMDB';
end metadata;

from CMDB.SoftwareInstance_SoftwareServer import SoftwareInstance_SoftwareServer 4.0;

syncmapping getCert_SSL_Certificate 1.0
    """
        Traversys getCert Sync Pattern.

        Change History:
        2021-09-27 1.0 : WMF : Created.

    """
    overview
        tags getCert, Traversys;
    end overview;

    mapping from SoftwareInstance_SoftwareServer.softwareinstance as si
        traverse ElementWithDetail:Detail:Detail:Detail where type = "SSL Certificate" as ssl_dt
            doc -> BMC_Document;
        end traverse;
    end mapping;

    body
        ss := SoftwareInstance_SoftwareServer.softwareserver

        for each ssl_dt do

            doc:= sync.shared.BMC_Document(
                                            key:= ssl_dt.key,
                                            name:= ssl_dt.name,
                                            ShortDescription:= ssl_dt.short_name,
                                            Description:= ssl_dt.common_name,
                                            Author:= ssl_dt.issuer,
                                            DocumentType:= "TLS Certificate",
                                            EndDate:= ssl_dt.expiry_date,
                                            SerialNumber:= ssl_dt.serial,
                                            StartDate:= ssl_dt.start_date,
                                            Company:= ss.Company,
                                            Category:= "Software",
                                            Type:= "TLS Certificate",
                                            Item:= "BMC Discovered"
                                            );

            sync.rel.BMC_Dependency(Source:= doc, Destination:= ss, Name:= "CERTIFICATE");

        end for;

    end body;

end syncmapping;