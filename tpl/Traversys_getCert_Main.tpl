// (c) Copyright 2015-2020, Traversys Limited

tpl 1.18 module Traversys_SSL_getCert_Main;

metadata
    __name:='Traversys getCert Main';
    description:='Traversys getCert Main';
    tree_path:='Traversys', 'SSL Discovery', 'getCert Main';
end metadata;

from Traversys_SSL_getCert_Functions import traversysGlobalDefs 1.6;

configuration traversysConfig 1.2

    """This definitions block is used by the getCert pattern."""

    //"Install Directory" install_dir := ~INSTALLDIR~;
    "Install Directory" install_dir := "/usr/tideway/data/customer";

    "Break inference relationship?"                           break_relationship  := false;

    "Artificially age out certificates (7 days)?"             aging               := false;

    "Attempt to map SSL Certificates to Discovered Device?"   map_device          := true;

    "Attempt to map SSL Certificates using Common Name?"      map_name            := true;

    "Set Removal Group?"                                      rem_group           := true;

    "Infer File node?"                                        file                := true;

    "Link to Discovery SI?"                                   link_file           := true;

end configuration;

definitions newDefs 1.0
    """
        Test Defs.

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

end definitions;

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

        getCert_host := discovery.dataSource("getCert");

        // License and Validation check
        xml, ip_addrs, valid := newDefs.validationCheck(getCert_host, traversysConfig.install_dir);

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
