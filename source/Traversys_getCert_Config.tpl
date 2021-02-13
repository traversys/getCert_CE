// (c) Copyright 2015-2020, Traversys Limited

///////////////////////////////////////////////////////////////////////////////////
//                                                                               //
// CAUTION: DO NOT attempt to MODIFY or REMOVE the Traversys_SSL_getCert_License //
// Pattern Module otherwise it will not only cause the license and validation to //
// fail, but failure of getCert CLI scripts to run.                              //
//                                                                               //
// This pattern is not configurable and is required to perform the validation    //
// You can customise how the SSL Certificats are modelled within the             //
// Traversys_SSL_getCert pattern module.                                         //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////

tpl 1.15 module Traversys_SSL_getCert_Config;

metadata
    __name:='Traversys getCert Config';
    description:='Traversys getCert Configuration';
    tree_path:='Traversys', 'SSL Discovery', 'getCert Config';
end metadata;

from Traversys_SSL_getCert_Functions import traversysGlobalDefs 1.6;

configuration traversysConfig 1.2

    """This definitions block is used by the getCert pattern."""

    "Install Directory" install_dir := ~INSTALLDIR~;

    "Break inference relationship?"                           break_relationship  := false;

    "Artificially age out certificates (7 days)?"             aging               := false;

    "Attempt to map SSL Certificates to Discovered Device?"   map_device          := true;

    "Attempt to map SSL Certificates using Common Name?"      map_name            := true;

    "Set Removal Group?"                                      rem_group           := false;

    "Infer File node?"                                        file                := true;

    "Link to Discovery SI?"                                   link_file           := true;

end configuration;

pattern Traversys_getCert_Config 1.0
    '''
    Generates the SSL Certificate XML file.

    (c) Copyright 2015-2020, Traversys Limited

    Change History:
    2020-04-13 1.0  WMF  :  Created.

    '''

    overview
        tags ssl, getCert, traversys;
    end overview;

    triggers
        on si:=SoftwareInstance created, confirmed where type = "BMC Discovery" or type = "BMC Atrium Discovery and Dependency Mapping";
    end triggers;

    body

        host:= related.host(si);

        // License and Validation check
        xml, ip_addrs, valid := traversysGlobalDefs.validationCheck(host, traversysConfig.install_dir);

        if not valid then
            log.warn("Validation check failed, check the logs!");
            stop;
        end if;

        if traversysConfig.file then

            f:= model.File( key:= si.key,
                            name:= "getCert XML",
                            content:= xml,
                            md5sum:= text.hash(xml),
                            path:= "%traversysConfig.install_dir%/temp/ssl-out.xml"
                          );
             model.setRemovalGroup(f, "SSL File");

             if traversysConfig.link_file then
                model.rel.RelatedFile(ElementUsingFile := si, File := f);
             end if;

        end if;

        // Optional artificial aging - 7 days for inferred nodes only
        traversysGlobalDefs.age(traversysConfig.aging);

        // Attribute cleanup - Inferred nodes only
        traversysGlobalDefs.att_cleanup();

    end body;

end pattern;
