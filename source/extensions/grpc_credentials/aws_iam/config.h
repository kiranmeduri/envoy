#pragma once

#include "envoy/config/grpc_credential/v2alpha/aws_iam.pb.validate.h"
#include "envoy/grpc/google_grpc_creds.h"

#include "extensions/filters/http/common/aws/signer.h"
#include "extensions/grpc_credentials/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace GrpcCredentials {
namespace AwsIam {

/**
 * AWS IAM based gRPC channel credentals factory.
 */
class AwsIamGrpcCredentialsFactory : public Grpc::GoogleGrpcCredentialsFactory {
public:
  virtual std::shared_ptr<grpc::ChannelCredentials>
  getChannelCredentials(const envoy::api::v2::core::GrpcService& grpc_service_config,
                        Api::Api& api) override;

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() {
    return std::make_unique<envoy::config::grpc_credential::v2alpha::AwsIamConfig>();
  }

  std::string name() const override { return GrpcCredentialsNames::get().AwsIam; }
};

/**
 * Produce AWS Sigv4 signature metadata for a gRPC message.
 */
class AwsIamHeaderAuthenticator : public grpc::MetadataCredentialsPlugin {
public:
  AwsIamHeaderAuthenticator(HttpFilters::Common::Aws::SignerPtr signer)
      : signer_(std::move(signer)) {}

  grpc::Status GetMetadata(grpc::string_ref, grpc::string_ref, const grpc::AuthContext&,
                           std::multimap<grpc::string, grpc::string>* metadata) override;

  bool IsBlocking() const { return true; }

private:
  HttpFilters::Common::Aws::SignerPtr signer_;
};

} // namespace AwsIam
} // namespace GrpcCredentials
} // namespace Extensions
} // namespace Envoy
