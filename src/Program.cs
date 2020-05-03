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
                                foreach (NessusPatchData data in patchDataList) {
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
            
            logger.Info("Report Message Client: setting up the OpenRMF System Delete for Report subscription");
            IAsyncSubscription asyncSystemDelete = c.SubscribeAsync("openrmf.system.delete", deleteSystemData);
            logger.Info("Report Message Client: setting up the OpenRMF Nessus ACAS Patch Scan for Report subscription");
            IAsyncSubscription asyncSystemPatchScan = c.SubscribeAsync("openrmf.system.patchscan", updateSystemPatchScanData);
        }
        private static ObjectId GetInternalId(string id)
        {
            ObjectId internalId;
            if (!ObjectId.TryParse(id, out internalId))
                internalId = ObjectId.Empty;
            return internalId;
        }
    }
}
