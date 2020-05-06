using Xunit;
using openrmf_msg_report.Models;
using System;

namespace tests.Models
{
    public class NessusPatchDataTests
    {
        [Fact]
        public void Test_NewNessusPatchDataIsValid()
        {
            NessusPatchData data = new NessusPatchData();
            Assert.True(data != null);
        }
    
        [Fact]
        public void Test_NessusPatchDataWithDataIsValid()
        {
            NessusPatchData data = new NessusPatchData();
            data.created = DateTime.Now;
            data.systemGroupId = "875678654gghjghjkgu658";
            data.hostname = "myHost";
            data.reportName = "My Report Here";
            data.updatedOn = DateTime.Now;
            data.operatingSystem = "Windows";
            data.systemType = "My System Type";
            data.ipAddress = "10.10.10.111";
            data.credentialed = true;
            data.pluginId = "9689658";
            data.pluginName = "My Plugin";
            data.family = "My Family";
            data.severity = 4;
            data.hostTotal = 2;
            data.total = 3;
            data.description = "This is my description";
            data.publicationDate = "March 31, 2020";
            data.pluginType = "My Plugin Type";
            data.riskFactor = "My Risk";
            data.synopsis = "My synopsis";

            // test things out
            Assert.True(data != null);
            Assert.True (!string.IsNullOrEmpty(data.created.ToShortDateString()));
            Assert.True (!string.IsNullOrEmpty(data.systemGroupId));
            Assert.True (!string.IsNullOrEmpty(data.hostname));
            Assert.True (!string.IsNullOrEmpty(data.reportName));
            Assert.True (!string.IsNullOrEmpty(data.operatingSystem));
            Assert.True (!string.IsNullOrEmpty(data.systemType));
            Assert.True (!string.IsNullOrEmpty(data.ipAddress));
            Assert.True (!string.IsNullOrEmpty(data.pluginId));
            Assert.True (!string.IsNullOrEmpty(data.pluginName));
            Assert.True (!string.IsNullOrEmpty(data.family));
            Assert.True (!string.IsNullOrEmpty(data.description));
            Assert.True (!string.IsNullOrEmpty(data.publicationDate));
            Assert.True (!string.IsNullOrEmpty(data.pluginType));
            Assert.True (!string.IsNullOrEmpty(data.riskFactor));
            Assert.True (!string.IsNullOrEmpty(data.synopsis));
            Assert.True (data.severityName == "Critical");
            Assert.True (data.updatedOn.HasValue);
            Assert.True (!string.IsNullOrEmpty(data.updatedOn.Value.ToShortDateString()));
        }
    }
}
