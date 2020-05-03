// Copyright (c) Cingulara LLC 2019 and Tutela LLC 2019. All rights reserved.
// Licensed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 license. See LICENSE file in the project root for full license information.
using openrmf_msg_report.Models;
using System.Collections.Generic;
using System;
using System.Threading.Tasks;
using MongoDB.Driver;
using MongoDB.Bson;

namespace openrmf_msg_report.Data {
    public class ReportRepository : IReportRepository
    {
        private readonly ReportContext _context = null;

        public ReportRepository(Settings settings)
        {
            _context = new ReportContext(settings);
        }

        // get all patch scan data for a given System and return the listing
        public async Task<IEnumerable<NessusPatchData>> GetAllPatchScanDataBySystemGroup(string id)
        {
            try
            {
                //ObjectId internalId = GetInternalId(id);
                return await _context.ACASScanReports
                        .Find(data => data.systemGroupId == id).ToListAsync();
            }
            catch (Exception ex)
            {
                // log or manage the exception
                throw ex;
            }
        }

        private ObjectId GetInternalId(string id)
        {
            ObjectId internalId;
            if (!ObjectId.TryParse(id, out internalId))
                internalId = ObjectId.Empty;

            return internalId;
        }
        
        // add a single Patch Scan Data record
        public async Task<NessusPatchData> AddPatchScanData(NessusPatchData data)
        {
            try
            {
                await _context.ACASScanReports.InsertOneAsync(data);
                return data;
            }
            catch (Exception ex)
            {
                // log or manage the exception
                throw ex;
            }
        }

        // delete all report data across all collections when a system is deleted
        public async Task<bool> DeleteAllSystemData(string id)
        {
            try
            {
                DeleteResult actionResult 
                    = await _context.ACASScanReports.DeleteManyAsync(
                        Builders<NessusPatchData>.Filter.Eq("systemGroupId", id));

                return actionResult.IsAcknowledged 
                    && actionResult.DeletedCount > 0;
            }
            catch (Exception ex)
            {
                // log or manage the exception
                throw ex;
            }
        }

        // delete just the ACAS / Patch scan data for a system only
        public async Task<bool> DeletePatchScanDataBySystemGroup(string id)
        {
            try
            {
                DeleteResult actionResult 
                    = await _context.ACASScanReports.DeleteManyAsync(
                        Builders<NessusPatchData>.Filter.Eq("systemGroupId", id));

                return actionResult.IsAcknowledged 
                    && actionResult.DeletedCount > 0;
            }
            catch (Exception ex)
            {
                // log or manage the exception
                throw ex;
            }
        }


    }
}