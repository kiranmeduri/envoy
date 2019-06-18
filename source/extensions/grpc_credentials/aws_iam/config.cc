#include "extensions/grpc_credentials/aws_iam/config.h"

#include "envoy/api/v2/core/grpc_service.pb.h"
#include "envoy/common/exception.h"
#include "envoy/config/grpc_credential/v2alpha/aws_iam.pb.validate.h"
#include "envoy/grpc/google_grpc_creds.h"
#include "envoy/registry/registry.h"

#include "common/config/utility.h"
#include "common/grpc/google_grpc_creds_impl.h"
#include "common/http/headers.h"
#include "common/http/message_impl.h"
#include "common/http/utility.h"
#include "common/protobuf/message_validator_impl.h"

#include "extensions/filters/http/common/aws/credentials_provider_impl.h"
#include "extensions/filters/http/common/aws/region_provider_impl.h"
#include "extensions/filters/http/common/aws/signer_impl.h"
#include "extensions/filters/http/common/aws/utility.h"

namespace Envoy {
namespace Extensions {
namespace GrpcCredentials {
namespace AwsIam {

using namespace HttpFilters::Common::Aws;

namespace Util {

/**
 * Constructs an HTTP message to be AWS Sigv4 signed.
 *
 * @param service_url Service url as passed to the MetadataCredentialsPlugin::GetMetadata()
 * @param method_name Method name as passed to the MetadataCredentialsPlugin::GetMetadata()
 * @return HTTP message to be signed
 */
static Http::RequestMessageImpl buildMessageToSign(grpc::string_ref service_url,
                                                   grpc::string_ref method_name) {

  const std::string uri = fmt::format("{}/{}", std::string(service_url.data(), service_url.size()),
                                      std::string(method_name.data(), method_name.size()));
  absl::string_view host;
  absl::string_view path;
  Http::Utility::extractHostPathFromUri(uri, host, path);

  Http::RequestMessageImpl message;
  message.headers().insertMethod().value().setReference(Http::Headers::get().MethodValues.Post);
  message.headers().insertHost().value(host);
  message.headers().insertPath().value(path);

  return message;
}

/**
 * Transform AWS Sigv4 signed HTTP headers into the gRPC credentials metadata
 *
 * @param Sigv4 signed HTTP headers
 * @param Output gRPC credentials metadata
 */
static void signedHeadersToMetadata(const Http::HeaderMap& headers,
                                    std::multimap<grpc::string, grpc::string>* metadata) {

  headers.iterate(
      [](const Http::HeaderEntry& entry, void* context) -> Http::HeaderMap::Iterate {
        auto* md = static_cast<decltype(metadata)>(context);
        const auto& key = entry.key().getStringView();
        // Skip pseudo-headers
        if (key.empty() || key[0] == ':') {
          return Http::HeaderMap::Iterate::Continue;
        }
        md->emplace(key, entry.value().getStringView());
        return Http::HeaderMap::Iterate::Continue;
      },
      metadata);
}

/*
 * Determine AWS region.
 *
 * Will throw an exception in case it was unable to determine the region.
 *
 * @param config AWS IAM gRPC credentials plugin config
 * @return AWS region name
 */
static std::string getRegion(const envoy::config::grpc_credential::v2alpha::AwsIamConfig& config) {
  std::unique_ptr<RegionProvider> region_provider;
  if (!config.region().empty()) {
    region_provider.reset(new StaticRegionProvider(config.region()));
  } else {
    region_provider.reset(new EnvironmentRegionProvider());
  }

  if (!region_provider->getRegion().has_value()) {
    throw EnvoyException("Could not determine AWS region. "
                         "If you are not running Envoy in EC2 or ECS, "
                         "provide the region in the plugin configuration.");
  }

  return *region_provider->getRegion();
}

} // namespace Util

std::shared_ptr<grpc::ChannelCredentials> AwsIamGrpcCredentialsFactory::getChannelCredentials(
    const envoy::api::v2::core::GrpcService& grpc_service_config, Api::Api& api) {

  const auto& google_grpc = grpc_service_config.google_grpc();
  std::shared_ptr<grpc::ChannelCredentials> creds =
      Grpc::CredsUtility::defaultSslChannelCredentials(grpc_service_config, api);

  std::shared_ptr<grpc::CallCredentials> call_creds = nullptr;
  for (const auto& credential : google_grpc.call_credentials()) {
    switch (credential.credential_specifier_case()) {
    case envoy::api::v2::core::GrpcService::GoogleGrpc::CallCredentials::kFromPlugin: {
      if (credential.from_plugin().name() == GrpcCredentialsNames::get().AwsIam) {
        AwsIamGrpcCredentialsFactory credentials_factory;
        const Envoy::ProtobufTypes::MessagePtr config_message =
            Envoy::Config::Utility::translateToFactoryConfig(
                credential.from_plugin(), ProtobufMessage::getNullValidationVisitor(),
                credentials_factory);
        const auto& config = Envoy::MessageUtil::downcastAndValidate<
            const envoy::config::grpc_credential::v2alpha::AwsIamConfig&>(*config_message);
        auto credentials_provider =
            std::make_shared<DefaultCredentialsProviderChain>(api, Utility::metadataFetcher);
        auto signer = std::make_unique<SignerImpl>(config.service_name(), Util::getRegion(config),
                                                   credentials_provider, api.timeSource());
        std::shared_ptr<grpc::CallCredentials> new_call_creds = grpc::MetadataCredentialsFromPlugin(
            std::make_unique<AwsIamHeaderAuthenticator>(std::move(signer)));
        if (call_creds == nullptr) {
          call_creds = new_call_creds;
        } else {
          call_creds = grpc::CompositeCallCredentials(call_creds, new_call_creds);
        }
      }
      break;
    }
    default:
      // unused credential types
      continue;
    }
  }

  if (call_creds != nullptr) {
    return grpc::CompositeChannelCredentials(creds, call_creds);
  }

  return creds;
}

grpc::Status
AwsIamHeaderAuthenticator::GetMetadata(grpc::string_ref service_url, grpc::string_ref method_name,
                                       const grpc::AuthContext&,
                                       std::multimap<grpc::string, grpc::string>* metadata) {

  Http::RequestMessageImpl message = Util::buildMessageToSign(service_url, method_name);

  try {
    signer_->sign(message, false);
  } catch (const EnvoyException& e) {
    return grpc::Status(grpc::StatusCode::INTERNAL, e.what());
  }

  Util::signedHeadersToMetadata(message.headers(), metadata);

  return grpc::Status::OK;
}

REGISTER_FACTORY(AwsIamGrpcCredentialsFactory, Grpc::GoogleGrpcCredentialsFactory);

} // namespace AwsIam
} // namespace GrpcCredentials
} // namespace Extensions
} // namespace Envoy
