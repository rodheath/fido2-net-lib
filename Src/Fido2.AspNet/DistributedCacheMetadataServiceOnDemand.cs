using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class DistributedCacheMetadataServiceOnDemand : IMetadataService
    {
        protected readonly IDistributedCache _cache;
        protected readonly List<IMetadataRepository> _repositories;
        protected readonly ILogger<DistributedCacheMetadataServiceOnDemand> _log;
        protected bool _initialized;
        protected readonly TimeSpan _defaultCacheInterval = TimeSpan.FromHours(25);

        protected readonly ConcurrentDictionary<Guid, MetadataStatement> _metadataStatements;
        protected readonly ConcurrentDictionary<Guid, MetadataTOCPayloadEntry> _entries;

        protected const string CACHE_PREFIX = "DistributedCacheMetadataServiceOnDemand";

        public DistributedCacheMetadataServiceOnDemand(
            IEnumerable<IMetadataRepository> repositories,
            IDistributedCache cache,
            ILogger<DistributedCacheMetadataServiceOnDemand> log)
        {
            _repositories = repositories.ToList();
            _cache = cache;
            _metadataStatements = new ConcurrentDictionary<Guid, MetadataStatement>();
            _entries = new ConcurrentDictionary<Guid, MetadataTOCPayloadEntry>();
            _log = log;
        }

        public virtual bool ConformanceTesting()
        {
            return _repositories.FirstOrDefault()?.GetType() == typeof(ConformanceMetadataRepository);
        }
        
        public virtual MetadataTOCPayloadEntry GetEntry(Guid aaguid)
        {
            MetadataTOCPayloadEntry entry = null;
            if (_entries.ContainsKey(aaguid))
            {
                entry = _entries[aaguid];
            }
            else
            {
                foreach (var client in _repositories)
                {
                    try
                    {
                        var tocCacheKey = GetTocCacheKey(client);

                        var cachedToc = _cache.GetString(tocCacheKey);
                        MetadataTOCPayload toc;

                        DateTime? cacheUntil = null;

                        if (!string.IsNullOrEmpty(cachedToc))
                        {
                            toc = JsonConvert.DeserializeObject<MetadataTOCPayload>(cachedToc);
                            cacheUntil = GetCacheUntilTime(toc);
                        }
                        else
                        {
                            _log?.LogInformation("TOC not cached so loading from MDS...");

                            try
                            {
                                toc = client.GetToc().Result;
                            }
                            catch (Exception ex)
                            {
                                _log?.LogError(ex, "Error getting TOC from {0}", client.GetType().Name);
                                throw;
                            }

                            _log?.LogInformation("TOC not cached so loading from MDS... Done.");

                            cacheUntil = GetCacheUntilTime(toc);

                            if (cacheUntil.HasValue)
                            {
                                _cache.SetString(
                                    tocCacheKey,
                                    JsonConvert.SerializeObject(toc),
                                    new DistributedCacheEntryOptions()
                                    {
                                        AbsoluteExpiration = cacheUntil
                                    });
                            }
                        }

                        entry = toc.Entries.Where(entry => string.Equals(entry.AaGuid, aaguid.ToString(), StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                        if (entry != null && _entries.TryAdd(Guid.Parse(entry.AaGuid), entry))
                        {
                            // Load if it doesn't already exist
                            LoadEntryStatement(client, toc, entry, cacheUntil);
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Throw and log this as we want issues with external services to be known
                        _log.LogCritical(ex, "Error initialising MDS client '{0}'", client.GetType().Name);
                        throw new Fido2MetadataException("Error getting metadata TOC payload entry", ex);
                    }
                }
            }

            if (_metadataStatements.ContainsKey(aaguid))
            {
                entry.MetadataStatement = _metadataStatements[aaguid];
            }

            return entry;
        }

        protected virtual string GetTocCacheKey(IMetadataRepository repository)
        {
            return $"{CACHE_PREFIX}:{repository.GetType().Name}:TOC";
        }

        protected virtual string GetEntryCacheKey(IMetadataRepository repository, Guid aaGuid)
        {
            return $"{CACHE_PREFIX}:{repository.GetType().Name}:Entry:{aaGuid}";
        }

        protected virtual void LoadEntryStatement(IMetadataRepository repository, MetadataTOCPayload toc, MetadataTOCPayloadEntry entry, DateTime? cacheUntil = null)
        {
            if (entry.AaGuid != null)
            {
                var cacheKey = GetEntryCacheKey(repository, Guid.Parse(entry.AaGuid));

                var cachedEntry = _cache.GetString(cacheKey);
                if (cachedEntry != null)
                {
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(cachedEntry);
                    if (!string.IsNullOrWhiteSpace(statement.AaGuid))
                        _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);
                }
                else
                {
                    _log?.LogInformation("Entry for {0}/{1} not cached so loading from MDS...", entry.AaGuid, entry.Aaid);

                    try
                    {
                        var statement = repository.GetMetadataStatement(toc, entry).Result;

                        if (!string.IsNullOrWhiteSpace(statement.AaGuid))
                        {
                            _metadataStatements.TryAdd(Guid.Parse(statement.AaGuid), statement);

                            var statementJson = JsonConvert.SerializeObject(statement, Formatting.Indented);

                            if (cacheUntil.HasValue)
                            {
                                _cache.SetString(cacheKey, statementJson, new DistributedCacheEntryOptions
                                {
                                    AbsoluteExpiration = cacheUntil
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log?.LogError(ex, "Error getting MetadataStatement from {0} for AAGUID '{1}' ", repository.GetType().Name, entry.AaGuid);
                        throw;
                    }
                }
            }
        }

        private DateTime? GetCacheUntilTime(MetadataTOCPayload toc)
        {
            if (!string.IsNullOrWhiteSpace(toc?.NextUpdate)
                && DateTime.TryParseExact(
                    toc.NextUpdate,
                    new[] { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "o" }, //Sould be ISO8601 date but allow for other ISO formats too
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out var parsedDate))
            {
                //NextUpdate is in the past to default to a useful number that will result us cross the date theshold for the next update
                if (parsedDate < DateTime.UtcNow.AddMinutes(5))
                    return DateTime.UtcNow.Add(_defaultCacheInterval);

                return parsedDate;
            }

            return null;
        }

        public virtual async Task Initialize()
        {
            await Task.FromResult(0);
        }

        public virtual bool IsInitialized()
        {
            return true;
        }
    }
}
