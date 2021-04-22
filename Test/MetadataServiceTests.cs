using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Test
{
    public class MetadataServiceTests
    {

        [Fact]
        public async Task ConformanceTestClient()
        {
            var client = new ConformanceMetadataRepository(null, "http://localhost");

            var toc = await client.GetToc();

            Assert.True(toc.Entries.Length > 0);

            var entry_1 = await client.GetMetadataStatement(toc, toc.Entries[toc.Entries.Length - 1]);

            Assert.NotNull(entry_1.Description);

        }

        [Fact]
        public async Task DistributedCacheMetadataService_Works()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(DateTime.UtcNow.AddDays(5));

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.NotNull(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataService_CacheSuppressionWorks()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(null);

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataService(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataService>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataService:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.Null(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataServiceOnDemand_Works()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(DateTime.UtcNow.AddDays(5));

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.NotNull(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataServiceOnDemand_CacheSuppressionWorks()
        {
            var services = new ServiceCollection();

            var staticClient = new StaticMetadataRepository(null);

            var clients = new List<IMetadataRepository>();

            clients.Add(staticClient);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            var entry = service.GetEntry(Guid.Parse("6d44ba9b-f6ec-2e49-b930-0c8fe920cb73"));

            Assert.True(entry.MetadataStatement.Description == "Yubico Security Key NFC");

            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:StaticMetadataRepository:Entry:6d44ba9b-f6ec-2e49-b930-0c8fe920cb73");

            Assert.Null(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataServiceOnDemand_CheckFileSystemRepository_Defaults()
        {
            var services = new ServiceCollection();

            var fileSystemRepo = new FileSystemMetadataRepository("MDSCacheDirPath");

            var clients = new List<IMetadataRepository>();

            clients.Add(fileSystemRepo);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            // Try to get the entry for a guid we know does not exist in our MDSCacheDirPath folder
            var entry = service.GetEntry(Guid.Parse("ac22a66d-40b9-4d67-b784-9686b5c09da8"));
            Assert.Null(entry);

            // Try to get the entry for a guid we know does exist in our MDSCacheDirPath folder
            entry = service.GetEntry(Guid.Parse("177de07d-794c-4d63-afcf-14e06b67969b"));
            Assert.NotNull(entry.MetadataStatement);

            // With no TOC file the status report should be NOT_FIDO_CERTIFIED
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.NOT_FIDO_CERTIFIED);

            // Try to get the entry for a guid we know does exist in our MDSCacheDirPath folder
            entry = service.GetEntry(Guid.Parse("406e9911-74a3-4dbf-94b8-052917c67d59"));
            Assert.NotNull(entry.MetadataStatement);

            // With no TOC file the status report should be NOT_FIDO_CERTIFIED
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.NOT_FIDO_CERTIFIED);

            // With no TOC file nextUpdate defaults to an empty string so we should see null cache entries.
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:177de07d-794c-4d63-afcf-14e06b67969b");
            Assert.Null(cacheEntry);
            cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:406e9911-74a3-4dbf-94b8-052917c67d59");
            Assert.Null(cacheEntry);
        }

        [Theory]
        [InlineData(null, 0)]
        [InlineData(null, 100)]
        [InlineData("", 0)]
        [InlineData("", 100)]
        public async Task DistributedCacheMetadataServiceOnDemand_CheckFileSystemRepository_NoTOCName(string tocName, int cacheTimeDaysFromNow)
        {
            var services = new ServiceCollection();

            var fileSystemRepo = new FileSystemMetadataRepository("MDSCacheDirPath", tocName, cacheTimeDaysFromNow);

            var clients = new List<IMetadataRepository>();

            clients.Add(fileSystemRepo);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            // Try to get the entry for a guid we know does not exist in our MDSCacheDirPath folder
            var entry = service.GetEntry(Guid.Parse("ac22a66d-40b9-4d67-b784-9686b5c09da8"));
            Assert.Null(entry);

            // Try to get the entry for a guid we know does exist in our MDSCacheDirPath folder
            entry = service.GetEntry(Guid.Parse("177de07d-794c-4d63-afcf-14e06b67969b"));
            Assert.NotNull(entry.MetadataStatement);

            // With no TOC file the status report should be NOT_FIDO_CERTIFIED
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.NOT_FIDO_CERTIFIED);

            // Try to get the entry for a guid we know does exist in our MDSCacheDirPath folder
            entry = service.GetEntry(Guid.Parse("406e9911-74a3-4dbf-94b8-052917c67d59"));
            Assert.NotNull(entry.MetadataStatement);

            // With no TOC file the status report should be NOT_FIDO_CERTIFIED
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.NOT_FIDO_CERTIFIED);

            // With no TOC file nextUpdate defaults to an empty string so we should see null cache entries.
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:177de07d-794c-4d63-afcf-14e06b67969b");
            Assert.Null(cacheEntry);
            cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:406e9911-74a3-4dbf-94b8-052917c67d59");
            Assert.Null(cacheEntry);
        }

        [Fact]
        public async Task DistributedCacheMetadataServiceOnDemand_CheckFileSystemRepository_StatusReports_FromTOCName()
        {
            var services = new ServiceCollection();

            var fileSystemRepo = new FileSystemMetadataRepository("MDSCacheDirPath", "TOC/TOC.json");

            var clients = new List<IMetadataRepository>();

            clients.Add(fileSystemRepo);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            // Try to get the entry for a guid we know does not exist in our test TOC.json file
            var entry = service.GetEntry(Guid.Parse("ac22a66d-40b9-4d67-b784-9686b5c09da8"));
            Assert.Null(entry);

            // Try to get the entry for a guid we know does exist in our test TOC.json file
            entry = service.GetEntry(Guid.Parse("177de07d-794c-4d63-afcf-14e06b67969b"));
            Assert.NotNull(entry.MetadataStatement);

            // Check the entry has the expected status report FIDO_CERTIFIED_L1
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.FIDO_CERTIFIED_L1);

            // Try to get the entry for a guid we know does exist in our test TOC.json file
            entry = service.GetEntry(Guid.Parse("406e9911-74a3-4dbf-94b8-052917c67d59"));
            Assert.NotNull(entry.MetadataStatement);

            // Check the entry has the expected status report ATTESTATION_KEY_COMPROMISE
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE);

            // Our TOC file has nextUpdate set to an empty string so we should see null cache entries.
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:177de07d-794c-4d63-afcf-14e06b67969b");
            Assert.Null(cacheEntry);
            cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:406e9911-74a3-4dbf-94b8-052917c67d59");
            Assert.Null(cacheEntry);
        }

        [Theory]
        // Instead of taking the nextUpdate value from the TOC file (which is an empty string) we set it to our own value
        // Set cache time for 100 days from now
        [InlineData(100)]
        // Set cache time for one day in the past
        // This should force the default cache interval of 25 hours
        [InlineData(-1)]
        public async Task DistributedCacheMetadataServiceOnDemand_CheckFileSystemRepository_StatusReports_FromTOCName_OverrideNextUpdate(int cacheTimeDaysFromNow)
        {
            var services = new ServiceCollection();

            var fileSystemRepo = new FileSystemMetadataRepository("MDSCacheDirPath", "TOC/TOC.json", cacheTimeDaysFromNow);

            var clients = new List<IMetadataRepository>();

            clients.Add(fileSystemRepo);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            // Try to get the entry for a guid we know does not exist in our test TOC.json file
            var entry = service.GetEntry(Guid.Parse("ac22a66d-40b9-4d67-b784-9686b5c09da8"));
            Assert.Null(entry);

            // Try to get the entry for a guid we know does exist in our test TOC.json file
            entry = service.GetEntry(Guid.Parse("177de07d-794c-4d63-afcf-14e06b67969b"));
            Assert.NotNull(entry.MetadataStatement);

            // Check the entry has the expected status report FIDO_CERTIFIED_L1
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.FIDO_CERTIFIED_L1);

            // Try to get the entry for a guid we know does exist in our test TOC.json file
            entry = service.GetEntry(Guid.Parse("406e9911-74a3-4dbf-94b8-052917c67d59"));
            Assert.NotNull(entry.MetadataStatement);

            // Check the entry has the expected status report ATTESTATION_KEY_COMPROMISE
            Assert.True(entry.StatusReports.Length == 1);
            Assert.True(entry.StatusReports.FirstOrDefault().Status == AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE);

            // Our TOC file nextUpdate has been overridden with a non-null value so we should see non-null cache entries.
            var cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:177de07d-794c-4d63-afcf-14e06b67969b");
            Assert.NotNull(cacheEntry);
            cacheEntry = await memCache.GetStringAsync("DistributedCacheMetadataServiceOnDemand:FileSystemMetadataRepository:Entry:406e9911-74a3-4dbf-94b8-052917c67d59");
            Assert.NotNull(cacheEntry);
        }

        // This test is for the on-demand loading where values can be retrieved concurrently.
        // The TOC.json file, used in this test, has intentionally had the nextUpdate set
        // to an empty string to bypass the cache.
        [Fact]
        public async Task DistributedCacheMetadataServiceOnDemand_CheckFileSystemRepository_IsThreadSafe()
        {
            var services = new ServiceCollection();

            var fileSystemRepo = new FileSystemMetadataRepository("MDSCacheDirPath", "TOC/TOC.json");

            var clients = new List<IMetadataRepository>();

            clients.Add(fileSystemRepo);

            services.AddDistributedMemoryCache();
            services.AddLogging();

            var provider = services.BuildServiceProvider();

            var memCache = provider.GetService<IDistributedCache>();

            var service = new DistributedCacheMetadataServiceOnDemand(
                clients,
                memCache,
                provider.GetService<ILogger<DistributedCacheMetadataServiceOnDemand>>());

            await service.Initialize();

            bool passed = true;
            int iterations = 100;

            // Create two threads that will access the file system repository concurrently 
            Thread thread1 = new Thread(new ThreadStart(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    try
                    {
                        // By using a random Guid we bypass the cache
                        Guid id = Guid.NewGuid();
                        // call the code being thread safety checked
                        var entry = service.GetEntry(id);
                    }
                    catch (Exception)
                    {
                        // Typical threading inner exception: System.InvalidOperationException:
                        // "Operations that change non-concurrent collections must have exclusive access.
                        // A concurrent update was performed on this collection and corrupted its state.
                        // The collection's state is no longer correct."
                        passed = false;
                        break;
                    }
                }
            }));

            Thread thread2 = new Thread(new ThreadStart(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    try
                    {
                        // By using a random Guid we bypass the cache
                        Guid id = Guid.NewGuid();
                        // call the code being thread safety checked
                        var entry = service.GetEntry(id);
                    }
                    catch (Exception)
                    {
                        // Typical threading inner exception: System.InvalidOperationException:
                        // "Operations that change non-concurrent collections must have exclusive access.
                        // A concurrent update was performed on this collection and corrupted its state.
                        // The collection's state is no longer correct."
                        passed = false;
                        break;
                    }
                }
            }));

            // Start the two threads
            thread1.Start();
            thread2.Start();
            // Wait for them to complete and return to main thread
            thread1.Join();
            thread2.Join();
            // Check the results
            Assert.True(passed, "Code has failed this thread safety test");
        }
    }
}
