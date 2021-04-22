using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Fido2NetLibBuilderExtensions
    {
        public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<Fido2Configuration>(configuration);

            services.AddSingleton(
                resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

            services.AddServices();

            return new Fido2NetLibBuilder(services);
        }

        private static void AddServices(this IServiceCollection services)
        {
            services.AddTransient<IFido2, Fido2>();
            services.AddSingleton<IMetadataService, NullMetadataService>(); //Default implementation if we choose not to enable MDS
        }

        public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, Action<Fido2Configuration> setupAction)
        {
            services.Configure(setupAction);

            services.AddSingleton(
                resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

            services.AddServices();

            return new Fido2NetLibBuilder(services);
        }

        public static void AddCachedMetadataService(this IFido2NetLibBuilder builder, Action<IFido2MetadataServiceBuilder> configAction)
        {
            builder.AddMetadataService<DistributedCacheMetadataService>();

            configAction(new Fido2NetLibBuilder(builder.Services));
        }

        /// <summary>
        /// Adds a cached metadata service on demand.
        /// This method avoids the long delays seen when retrieving all of the
        /// metadata in one go at initialisation (typically ~30 seconds
        /// depending on network).  It fetches only the metadata requested for
        /// a particular aaguid on demand and once fetched it is cached in the
        /// normal way.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configAction"></param>
        public static void AddCachedMetadataServiceOnDemand(this IFido2NetLibBuilder builder, Action<IFido2MetadataServiceBuilder> configAction)
        {
            builder.AddMetadataService<DistributedCacheMetadataServiceOnDemand>();

            configAction(new Fido2NetLibBuilder(builder.Services));
        }

        /// <summary>
        /// Adds a file system metadata repository to the service collection
        /// with options.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="directoryPath">The directory where the individual
        /// metadata statement files are located.</param>
        /// <param name="tocName">The path with filename where the table of
        /// contents file is located.  This file is typically created by
        /// downloading it from the MDS server or hand crafting it depending on
        /// the customer's requirements.</param>
        /// <param name="cacheTimeDaysFromNow">This is used only when the tocName
        /// parameter is specified.  It is the number of days, from the current
        /// time, to cache the TOC for before re-reading it from the file system.
        /// If this parameter is not provided the default value of zero means
        /// the nextUpdate value read from the TOC file will be used.</param>
        /// <returns></returns>
        public static IFido2MetadataServiceBuilder AddFileSystemMetadataRepository(this IFido2MetadataServiceBuilder builder,
            string directoryPath,
            string tocName = null,
            int cacheTimeDaysFromNow = 0)
        {
            builder.Services.AddTransient<IMetadataRepository, FileSystemMetadataRepository>(r =>
            {
                return new FileSystemMetadataRepository(directoryPath, tocName, cacheTimeDaysFromNow);
            });

            return builder;
        }

        public static IFido2MetadataServiceBuilder AddStaticMetadataRepository(this IFido2MetadataServiceBuilder builder)
        {
            builder.Services.AddTransient<IMetadataRepository, StaticMetadataRepository>();

            return builder;
        }
        public static IFido2MetadataServiceBuilder AddConformanceMetadataRepository(
            this IFido2MetadataServiceBuilder builder,
            HttpClient client = null, 
            string origin = "")
        {
            builder.Services.AddTransient<IMetadataRepository>(provider =>
            {
                return new ConformanceMetadataRepository(client, origin);
            });

            return builder;
        }
        public static IFido2MetadataServiceBuilder AddFidoMetadataRepository(
            this IFido2MetadataServiceBuilder builder,
            string accessToken,
            HttpClient client = null)
        {
            builder.Services.AddTransient<IMetadataRepository>(provider =>
            {
                return new Fido2MetadataServiceRepository(accessToken, client);
            });

            return builder;
        }

        /// <summary>
        /// Method to add a FIDO metadata repository to the service collection
        /// with CRL checking option.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="accessToken">The FIDO alliance access token</param>
        /// <param name="disableCrlCheck">A flag to enable/disable CRL checking
        /// of the TOC certificate trust chain</param>
        /// <param name="tocRootCert">An optional FIDO metadata TOC root certificate</param>
        /// <param name="client"></param>
        /// <returns></returns>
        public static IFido2MetadataServiceBuilder AddFidoMetadataRepository(
            this IFido2MetadataServiceBuilder builder,
            string accessToken,
            bool disableCrlCheck,
            X509Certificate2 tocRootCert,
            HttpClient client = null)
        {
            builder.Services.AddTransient<IMetadataRepository>(provider =>
            {
                return new Fido2MetadataServiceRepository(accessToken, client, disableCrlCheck, tocRootCert);
            });

            return builder;
        }

        private static void AddMetadataService<TService>(this IFido2NetLibBuilder builder) where TService: class, IMetadataService
        {
            builder.Services.AddSingleton<TService>();

            //Use factory method and concrete type registration so we can do the initialisation in here automatically
            builder.Services.AddSingleton<IMetadataService>(r =>
            {
                var service = r.GetService<TService>();
                service.Initialize().Wait();
                return service;
            });
        }
    }

    public interface IFido2NetLibBuilder
    {
        IServiceCollection Services { get; }
    }

    public interface IFido2MetadataServiceBuilder
    {
        IServiceCollection Services { get; }
    }

    public class Fido2NetLibBuilder : IFido2NetLibBuilder, IFido2MetadataServiceBuilder
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityServerBuilder"/> class.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <exception cref="System.ArgumentNullException">services</exception>
        public Fido2NetLibBuilder(IServiceCollection services)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
        }

        /// <summary>
        /// Gets the services.
        /// </summary>
        /// <value>
        /// The services.
        /// </value>
        public IServiceCollection Services { get; }
    }
}
