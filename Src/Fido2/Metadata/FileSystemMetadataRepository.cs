using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class FileSystemMetadataRepository : IMetadataRepository
    {
        protected readonly string _path;
        protected readonly string _tocName;
        protected readonly int _cacheTimeDaysFromNow;
        protected readonly ConcurrentDictionary<Guid, MetadataTOCPayloadEntry> _entries;
        private MetadataTOCPayload _toc;

        public FileSystemMetadataRepository(string path, string tocName = null, int cacheTimeDaysFromNow = 0)
        {
            _path = path;
            _tocName = tocName;
            _cacheTimeDaysFromNow = cacheTimeDaysFromNow;
            _entries = new ConcurrentDictionary<Guid, MetadataTOCPayloadEntry>();
        }

        public async Task<MetadataStatement> GetMetadataStatement(MetadataTOCPayload toc, MetadataTOCPayloadEntry entry)
        {
            if (_toc == null)
                _toc = await GetToc();

            if (!string.IsNullOrEmpty(entry.AaGuid) && Guid.TryParse(entry.AaGuid, out Guid parsedAaGuid))
            {
                if (_entries.ContainsKey(parsedAaGuid))
                    return _entries[parsedAaGuid].MetadataStatement;
            }

            return null;
        }

        public Task<MetadataTOCPayload> GetToc()
        {
            MetadataTOCPayload toc = null;
            FileInfo tocInfo = null;

            // Do we have a TOC file? If so try to load its contents.
            if (!string.IsNullOrEmpty(_tocName))
            {
                var rawToc = File.ReadAllText(_tocName);
                toc = JsonConvert.DeserializeObject<MetadataTOCPayload>(rawToc);
                tocInfo = new FileInfo(_tocName);
            }

            // Now look for the individual metadata statements
            if (Directory.Exists(_path))
            {
                foreach (var filename in Directory.GetFiles(_path))
                {
                    // For MacOS support
                    if (filename.Contains(".DS_Store"))
                    {
                        continue;
                    }

                    // If the TOC file has been placed in this folder
                    // we skip it because we have already read it in.
                    if (tocInfo != null)
                    {
                        FileInfo fileInfo = new FileInfo(filename);
                        if (fileInfo.FullName.Equals(tocInfo.FullName))
                        {
                            continue;
                        }
                    }

                    var rawStatement = File.ReadAllText(filename);
                    var statement = JsonConvert.DeserializeObject<MetadataStatement>(rawStatement);
                    var conformanceEntry = new MetadataTOCPayloadEntry
                    {
                        AaGuid = statement.AaGuid,
                        MetadataStatement = statement,
                        StatusReports = new StatusReport[] 
                        { 
                            new StatusReport 
                            { 
                                Status = AuthenticatorStatus.NOT_FIDO_CERTIFIED 
                            } 
                        }
                    };

                    if (null != conformanceEntry.AaGuid)
                        _entries.TryAdd(new Guid(conformanceEntry.AaGuid), conformanceEntry);
                }
            }

            // If we have a TOC.json file we start with that, as it contains valid
            // StatusReports, then copy over the data from the metadata statement files.
            if (tocInfo != null)
            {
                foreach (var tocEntry in toc.Entries)
                {
                    if (tocEntry.AaGuid == null)
                    {
                        continue;
                    }

                    var fileEntry = _entries.Where(entry => string.Equals(entry.Key.ToString(), tocEntry.AaGuid, StringComparison.OrdinalIgnoreCase)).FirstOrDefault().Value;
                    if (fileEntry != null)
                    {
                        tocEntry.MetadataStatement = fileEntry.MetadataStatement;
                    }
                }

                // Apply any override to the nextUpdate value read from the TOC file
                if (_cacheTimeDaysFromNow != 0)
                {
                    toc.NextUpdate = DateTime.UtcNow.Add(TimeSpan.FromDays(_cacheTimeDaysFromNow)).ToString("yyyy-MM-dd");
                }
            }
            else
            { 
                // We couldn't find a TOC.json file so we create a TOC with a fake header
                // and default values for the status reports and an empty next update.
                toc = new MetadataTOCPayload()
                {
                    Entries = _entries.Select(o => o.Value).ToArray(),
                    NextUpdate = "", //Empty means it won't get cached
                    LegalHeader = "Local FAKE",
                    Number = 1
                };
            }

            return Task.FromResult(toc);
        }
    }
}
