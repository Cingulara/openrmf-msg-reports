// Copyright (c) Cingulara LLC 2019 and Tutela LLC 2019. All rights reserved.
// Licensed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using NATS.Client;
using System.Text;
using NLog;
using NLog.Config;
using openrmf_msg_report.Models;
using openrmf_msg_report.Data;
using MongoDB.Bson;
using openrmf_msg_report.Classes;
using Newtonsoft.Json;
using System.Linq;

namespace openrmf_msg_report
{
    class Program
    {
        static void Main(string[] args)
        {
            LogManager.Configuration = new XmlLoggingConfiguration($"{AppContext.BaseDirectory}nlog.config");

            var logger = LogManager.GetLogger("openrmf_msg_report");
            
            // Create a new connection factory to create a connection.
            ConnectionFactory cf = new ConnectionFactory();
            // add the options for the server, reconnecting, and the handler events
            Options opts = ConnectionFactory.GetDefaultOptions();
            opts.MaxReconnect = -1;
            opts.ReconnectWait = 2000;
            opts.Name = "openrmf_msg_report";
            opts.Url = Environment.GetEnvironmentVariable("NATSSERVERURL");
            opts.AsyncErrorEventHandler += (sender, events) =>
            {
                logger.Info("NATS client error. Server: {0}. Message: {1}. Subject: {2}", events.Conn.ConnectedUrl, events.Error, events.Subscription.Subject);
            };

            opts.ServerDiscoveredEventHandler += (sender, events) =>
            {
                logger.Info("A new server has joined the cluster: {0}", events.Conn.DiscoveredServers);
            };

            opts.ClosedEventHandler += (sender, events) =>
            {
                logger.Info("Connection Closed: {0}", events.Conn.ConnectedUrl);
            };

            opts.ReconnectedEventHandler += (sender, events) =>
            {
                logger.Info("Connection Reconnected: {0}", events.Conn.ConnectedUrl);
            };

            opts.DisconnectedEventHandler += (sender, events) =>
            {
                logger.Info("Connection Disconnected: {0}", events.Conn.ConnectedUrl);
            };
            
            // Creates a live connection to the NATS Server with the above options
            IConnection c = cf.CreateConnection(opts);

            // update all report data when a system is deleted
            // openrmf.system.delete -- delete all system data for reporting based on the payload of System ID
            // get the ID, query for the system, delete all data
            EventHandler<MsgHandlerEventArgs> deleteSystemData = (sender, natsargs) =>
            {
                try {
                    // print the message
                    logger.Info("NATS Msg Checklists: {0}", natsargs.Message.Subject);
                    logger.Info("NATS Msg system data: {0}",Encoding.UTF8.GetString(natsargs.Message.Data));
                    
                    // setup the MondoDB connection
                    Settings s = new Settings();
                    s.ConnectionString = Environment.GetEnvironmentVariable("REPORTMONGODBCONNECTION");
                    s.Database = Environment.GetEnvironmentVariable("REPORTMONGODB");
                    // setup the database repo for reports to delete from
                    ReportRepository _reportRepo = new ReportRepository(s);
                    string systemGroupId = Encoding.UTF8.GetString(natsargs.Message.Data);
                    if (!string.IsNullOrEmpty(systemGroupId) ) {
                        bool deleted = _reportRepo.DeletePatchScanDataBySystemGroup(systemGroupId).Result;
                        if (deleted) {
                            logger.Info("Successfully deleted the system patch scan data for System Group {0}", systemGroupId);
                        } 
                        else {
                            logger.Warn("Did not delete the system patch scan data for System Group {0}. Maybe there is no data yet?", systemGroupId);
                        }
                    }
                    else {
                        logger.Warn("Warning: No System Group ID passed in when deleting System Report Patch Data system {0}", natsargs.Message.Subject);
                    }
                }
                catch (Exception ex) {
                    // log it here
                    logger.Error(ex, "Error retrieving system group record for system group");
                }
            };

            // update the Nessus ACAS Patch Data listing in the database
            // openrmf.system.patchscan -- take the system group ID from the data and process away
            EventHandler<MsgHandlerEventArgs> updateSystemPatchScanData = (sender, natsargs) =>
            {
                try {
                    // print the message
                    logger.Info("NATS Msg Checklists: {0}", natsargs.Message.Subject);
                    logger.Info("NATS Msg system data: {0}",Encoding.UTF8.GetString(natsargs.Message.Data));
                    
                    SystemGroup sg;
                    // setup the MondoDB connection
                    Settings s = new Settings();
                    s.ConnectionString = Environment.GetEnvironmentVariable("SYSTEMMONGODBCONNECTION");
                    s.Database = Environment.GetEnvironmentVariable("SYSTEMMONGODB");
                    // setup the database repo
                    SystemGroupRepository _systemGroupRepo = new SystemGroupRepository(s);
                    sg = _systemGroupRepo.GetSystemGroup(Encoding.UTF8.GetString(natsargs.Message.Data)).Result;
                    if (sg != null) {
                        // use the Report database connection
                        s.ConnectionString = Environment.GetEnvironmentVariable("REPORTMONGODBCONNECTION");
                        s.Database = Environment.GetEnvironmentVariable("REPORTMONGODB");
                        ReportRepository _reportRepo = new ReportRepository(s);
                        NessusPatchData result;
                        if (!string.IsNullOrEmpty(sg.rawNessusFile)) {
                            List<NessusPatchData> patchDataList = NessusPatchLoader.LoadPatchData(sg.rawNessusFile);
                            if (patchDataList != null && patchDataList.Count > 0) {
                                // delete the old data
                                bool deleted = _reportRepo.DeletePatchScanDataBySystemGroup(sg.InternalId.ToString()).Result;
                                // put in all the new data
                                foreach (NessusPatchData data in patchDataList) {
                                    data.systemGroupId = sg.InternalId.ToString();
                                    result = _reportRepo.AddPatchScanData(data).Result;
                                    if (result != null) {
                                        logger.Info("Report Message Client: Added scan plugin {0} for system group {1}", result.pluginId, result.systemGroupId);
                                    }
                                }
                            } else {
                                logger.Warn("Warning: Nessus Data loading was empty for System Group {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                            }
                        } else {
                            logger.Warn("Warning: Nessus Data is empty for System Group {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                        }
                    } 
                    else {
                        logger.Warn("Warning: bad System Group ID when updating the patch data {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                    }
                }
                catch (Exception ex) {
                    // log it here
                    logger.Error(ex, "Error retrieving system group record for system group id {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                }
            };
            
            // Setup a new Score record based on a new checklist uploaded
            // This is called from the Upload API to say "hey I have a new checklist, score it"
            EventHandler<MsgHandlerEventArgs> newChecklistVulnerabilities = (sender, natsargs) =>
            {
                try {
                    // print the message
                    logger.Info("New NATS subject: {0}", natsargs.Message.Subject);
                    logger.Info("New NATS data: {0}",Encoding.UTF8.GetString(natsargs.Message.Data));
                    Artifact checklist = GetChecklist(c, Encoding.UTF8.GetString(natsargs.Message.Data));
                    if (checklist.CHECKLIST == null)
                        checklist.CHECKLIST = ChecklistLoader.LoadChecklist(checklist.rawChecklist);
                    if (checklist != null && checklist.CHECKLIST != null) {
                        
                        List<VulnerabilityReport> vulnReport =  new List<VulnerabilityReport>(); // put all findings into a list and roll out
                        VulnerabilityReport vulnRecord; // put the individual record into
                        foreach (VULN vulnerability in checklist.CHECKLIST.STIGS.iSTIG.VULN) {

                            // grab pertinent information
                            vulnRecord = new VulnerabilityReport();
                            vulnRecord.systemGroupId = checklist.systemGroupId;
                            vulnRecord.artifactId = checklist.InternalId;
                            vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;
                            logger.Info("Getting Artifact {2} data for newChecklistVulnerabilities(system: {0}, vulnid: {1}) successfully", checklist.systemGroupId, vulnRecord.vulnid, checklist.InternalId.ToString());

                            // get the hostname from the ASSET record
                            if (!string.IsNullOrEmpty(checklist.CHECKLIST.ASSET.HOST_NAME)) 
                                vulnRecord.hostname = checklist.CHECKLIST.ASSET.HOST_NAME;
                            else 
                                vulnRecord.hostname = "Unknown";

                            // start getting the vulnerability detailed information
                            vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.checklistVersion = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "version").FirstOrDefault().SID_DATA;
                            vulnRecord.checklistRelease = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "releaseinfo").FirstOrDefault().SID_DATA;
                            vulnRecord.checklistType = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "title").FirstOrDefault().SID_DATA;
                            vulnRecord.comments = vulnerability.COMMENTS;
                            vulnRecord.details = vulnerability.FINDING_DETAILS;
                            vulnRecord.checkContent = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Check_Content").FirstOrDefault().ATTRIBUTE_DATA;                                
                            vulnRecord.discussion = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Discuss").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.fixText = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Fix_Text").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.ruleTitle = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Rule_Title").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.severity = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Severity").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.status = vulnerability.STATUS;
                            // get all the list of CCIs
                            foreach(STIG_DATA stig in vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "CCI_REF").ToList()) {
                                // add each one of these, from 0 to N of them
                                vulnRecord.cciList.Add(stig.ATTRIBUTE_DATA);
                            }
                            logger.Info("Adding Artifact {2} to the list for newChecklistVulnerabilities (system: {0}, vulnid: {1}) successfully", checklist.systemGroupId, vulnRecord.vulnid, checklist.InternalId.ToString());
                            vulnReport.Add(vulnRecord); // add it to the listing

                        } // for each VULN record
                        // save every single VULN record with the vuln number, artifactId and systemGroupId into the database

                        // setup the MondoDB connection
                        Settings s = new Settings();
                        s.ConnectionString = Environment.GetEnvironmentVariable("REPORTMONGODBCONNECTION");
                        s.Database = Environment.GetEnvironmentVariable("REPORTMONGODB");
                        // setup the database repo for reports to delete from
                        ReportRepository _reportRepo = new ReportRepository(s);
                        VulnerabilityReport result;
                        foreach (VulnerabilityReport record in vulnReport) {
                            result = _reportRepo.AddChecklistVulnerabilityData(record).Result;
                            if (result != null) 
                                logger.Info("Added vulnerability information on system {0} checklist {1} vulnerability {2}", result.systemGroupId, result.artifactId, result.vulnid);
                        }
                    }
                }
                catch (Exception ex) {
                    // log it here
                    logger.Error(ex, "Error saving new scoring information for artifactId {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                }
            };

            // Setup an updated Score record based on an updated checklist uploaded
            // This is called from the Upload API to say "hey I have an updated checklist, you may want to update your scoring"
            EventHandler<MsgHandlerEventArgs> updateChecklistVulnerabilities = (sender, natsargs) =>
            {
                try {
                    // print the message
                    logger.Info(natsargs.Message.Subject);
                    logger.Info(Encoding.UTF8.GetString(natsargs.Message.Data));
                    Artifact checklist = GetChecklist(c, Encoding.UTF8.GetString(natsargs.Message.Data));
                    if (checklist.CHECKLIST == null)
                        checklist.CHECKLIST = ChecklistLoader.LoadChecklist(checklist.rawChecklist);
                    if (checklist != null && checklist.CHECKLIST != null) {
                        List<VulnerabilityReport> vulnReport =  new List<VulnerabilityReport>(); // put all findings into a list and roll out
                        VulnerabilityReport vulnRecord; // put the individual record into
                        foreach (VULN vulnerability in checklist.CHECKLIST.STIGS.iSTIG.VULN) {
                            // grab pertinent information
                            vulnRecord = new VulnerabilityReport();
                            vulnRecord.systemGroupId = checklist.systemGroupId;
                            vulnRecord.artifactId = checklist.InternalId;
                            vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;
                            logger.Info("Getting Artifact {2} data for updateChecklistVulnerabilities(system: {0}, vulnid: {1}) successfully", checklist.systemGroupId, vulnRecord.vulnid, checklist.InternalId.ToString());

                            // get the hostname from the ASSET record
                            if (!string.IsNullOrEmpty(checklist.CHECKLIST.ASSET.HOST_NAME)) 
                                vulnRecord.hostname = checklist.CHECKLIST.ASSET.HOST_NAME;
                            else 
                                vulnRecord.hostname = "Unknown";

                            // start getting the vulnerability detailed information
                            vulnRecord.vulnid = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Num").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.checklistVersion = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "version").FirstOrDefault().SID_DATA;
                            vulnRecord.checklistRelease = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "releaseinfo").FirstOrDefault().SID_DATA;
                            vulnRecord.checklistType = checklist.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA.Where(x => x.SID_NAME == "title").FirstOrDefault().SID_DATA;
                            vulnRecord.comments = vulnerability.COMMENTS;
                            vulnRecord.details = vulnerability.FINDING_DETAILS;
                            vulnRecord.checkContent = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Check_Content").FirstOrDefault().ATTRIBUTE_DATA;                                
                            vulnRecord.discussion = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Vuln_Discuss").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.fixText = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Fix_Text").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.ruleTitle = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Rule_Title").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.severity = vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "Severity").FirstOrDefault().ATTRIBUTE_DATA;
                            vulnRecord.status = vulnerability.STATUS;
                            // get all the list of CCIs
                            foreach(STIG_DATA stig in vulnerability.STIG_DATA.Where(cc => cc.VULN_ATTRIBUTE == "CCI_REF").ToList()) {
                                // add each one of these, from 0 to N of them
                                vulnRecord.cciList.Add(stig.ATTRIBUTE_DATA);
                            }
                            logger.Info("Adding Artifact {2} to the list for updateChecklistVulnerabilities (system: {0}, vulnid: {1}) successfully", checklist.systemGroupId, vulnRecord.vulnid, checklist.InternalId.ToString());
                            vulnReport.Add(vulnRecord); // add it to the listing
                        } // for each VULN record
                        // save every single VULN record with the vuln number, artifactId and systemGroupId into the database

                        // setup the MondoDB connection
                        Settings s = new Settings();
                        s.ConnectionString = Environment.GetEnvironmentVariable("REPORTMONGODBCONNECTION");
                        s.Database = Environment.GetEnvironmentVariable("REPORTMONGODB");
                        // setup the database repo for reports to delete from
                        ReportRepository _reportRepo = new ReportRepository(s);
                        bool result;
                        foreach (VulnerabilityReport record in vulnReport) {
                            result = _reportRepo.UpdateChecklistVulnerabilityData(record).Result;
                            if (result) 
                                logger.Info("Updated vulnerability information on system {0} checklist {1} vulnerability {2}", record.systemGroupId, record.artifactId, record.vulnid);
                        }
                    }
                }
                catch (Exception ex) {
                    // log it here
                    logger.Error(ex, "Error saving updated scoring information for artifactId {0}", Encoding.UTF8.GetString(natsargs.Message.Data));
                }
            };

            logger.Info("Report Message Client: setting up the OpenRMF System Delete for Report subscription");
            IAsyncSubscription asyncSystemDelete = c.SubscribeAsync("openrmf.system.delete", deleteSystemData);
            logger.Info("Report Message Client: setting up the OpenRMF Nessus ACAS Patch Scan for Report subscription");
            IAsyncSubscription asyncSystemPatchScan = c.SubscribeAsync("openrmf.system.patchscan", updateSystemPatchScanData);
            logger.Info("Report Message Client: setting up the OpenRMF new vulnerabilities subscriptions");
            IAsyncSubscription asyncNew = c.SubscribeAsync("openrmf.checklist.save.new", newChecklistVulnerabilities);
            logger.Info("Report Message Client: setting up the OpenRMF update vulnerabilities subscriptions");
            IAsyncSubscription asyncUpdate = c.SubscribeAsync("openrmf.checklist.save.update", updateChecklistVulnerabilities);
        }
        private static ObjectId GetInternalId(string id)
        {
            ObjectId internalId;
            if (!ObjectId.TryParse(id, out internalId))
                internalId = ObjectId.Empty;
            return internalId;
        }

        /// <summary>
        /// Return a checklist record based on the ID requested. Uses a request/reply 
        /// method to get a checklist and then score it.
        /// </summary>
        /// <param name="conn">The database connection</param>
        /// <param name="id">The id of the checklist record to return</param>
        /// <returns>A checklist record, if found</returns>
        private static Artifact GetChecklist(IConnection conn, string id){
            try {
                Artifact art = new Artifact();
                Msg reply = conn.Request("openrmf.checklist.read", Encoding.UTF8.GetBytes(id), 10000); // publish to get this Artifact checklist back via ID
                // save the reply and get back the checklist to score
                if (reply != null) {
                    art = JsonConvert.DeserializeObject<Artifact>(Compression.DecompressString(Encoding.UTF8.GetString(reply.Data)));
                    return art;
                }
                return art;
            }
            catch (Exception ex) {
                Console.WriteLine(string.Format("openrmf-msg-score Error in GetChecklist with Artifact id {0}. Message: {1}",
                    id, ex.Message));
                throw ex;
            }
        }
    }
}
