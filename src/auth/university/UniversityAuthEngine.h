#pragma once

#include "auth/Auth.h"
#include "auth/AuthAuthorizeHandler.h"
#include "rgw/rgw_auth.h"
#include "include/str_map.h"
#include <memory>
#include <string>
#include <map>

namespace ceph {
namespace auth {
namespace university {

// Ontology-aware authorization info
struct OntologyAuthInfo {
  std::string university_id;
  std::string department;
  std::string role;  // professor, student, researcher, etc.
  std::vector<std::string> projects;  // research projects
  std::vector<std::string> collaborations;
  std::map<std::string, std::string> attributes;  // additional ontology attributes
  utime_t expires;
};

// University SSO token validator
class UniversityTokenValidator {
private:
  CephContext* cct;
  std::string sso_endpoint;
  std::string client_id;
  std::string client_secret;

public:
  UniversityTokenValidator(CephContext* cct, 
                          const std::string& endpoint,
                          const std::string& client_id,
                          const std::string& client_secret);

  // Validate university SSO token (SAML/OAuth2/Duo)
  int validate_token(const std::string& token, OntologyAuthInfo& auth_info);
  
  // Validate against university directory service
  int validate_university_identity(const std::string& university_id, 
                                  OntologyAuthInfo& auth_info);
};

// Ontology knowledge base interface
class OntologyKnowledgeBase {
private:
  CephContext* cct;
  std::string ontology_config_path;
  
public:
  OntologyKnowledgeBase(CephContext* cct, const std::string& config_path);
  
  // Query ontology for user permissions based on research context
  std::vector<std::string> get_permitted_datasets(const OntologyAuthInfo& auth_info);
  
  // Get file access permissions based on ontology rules
  int get_file_permissions(const OntologyAuthInfo& auth_info, 
                          const std::string& file_path,
                          unsigned int& permissions);
  
  // Check if user can access specific research data
  bool can_access_research_data(const OntologyAuthInfo& auth_info, 
                               const std::string& dataset_id,
                               const std::string& operation);
};

// Policy engine for fine-grained access control
class ResearchPolicyEngine {
private:
  CephContext* cct;
  OntologyKnowledgeBase* ontology_kb;
  
public:
  ResearchPolicyEngine(CephContext* cct, OntologyKnowledgeBase* kb);
  
  // Evaluate access policies based on ontology context
  AuthCapsInfo generate_capabilities(const OntologyAuthInfo& auth_info);
  
  // Generate CephFS path restrictions based on research projects
  std::string generate_path_restrictions(const OntologyAuthInfo& auth_info);
  
  // Check collaboration permissions
  bool check_collaboration_access(const OntologyAuthInfo& requester,
                                 const std::string& target_project);
};

// Main university authentication engine
class UniversityAuthEngine : public rgw::auth::Engine {
  using result_t = rgw::auth::Engine::result_t;
  using AuthInfo = rgw::auth::RemoteApplier::AuthInfo;
  
private:
  CephContext* cct;
  rgw::sal::Driver* driver;
  std::unique_ptr<UniversityTokenValidator> token_validator;
  std::unique_ptr<OntologyKnowledgeBase> ontology_kb;
  std::unique_ptr<ResearchPolicyEngine> policy_engine;
  const rgw::auth::RemoteApplier::Factory* apl_factory;

public:
  UniversityAuthEngine(CephContext* cct,
                      rgw::sal::Driver* driver,
                      const rgw::auth::RemoteApplier::Factory* apl_factory);
  
  const char* get_name() const noexcept override {
    return "rgw::auth::university::UniversityAuthEngine";
  }

  result_t authenticate(const DoutPrefixProvider* dpp,
                       const req_state* const s,
                       optional_yield y) const override;

private:
  result_t authenticate_university_token(const DoutPrefixProvider* dpp,
                                        const std::string& token,
                                        const req_state* const s,
                                        optional_yield y) const;
                                        
  AuthInfo build_auth_info(const OntologyAuthInfo& ontology_auth) const;
};

// Authorization handler for CephFS
class UniversityAuthorizeHandler : public AuthAuthorizeHandler {
private:
  std::unique_ptr<OntologyKnowledgeBase> ontology_kb;
  std::unique_ptr<ResearchPolicyEngine> policy_engine;

public:
  UniversityAuthorizeHandler(CephContext* cct);
  
  bool verify_authorizer(CephContext *cct,
                        const KeyStore& keys,
                        const ceph::bufferlist& authorizer_data,
                        size_t connection_secret_required_len,
                        ceph::bufferlist *authorizer_reply,
                        EntityName *entity_name,
                        uint64_t *global_id,
                        AuthCapsInfo *caps_info,
                        CryptoKey *session_key,
                        std::string *connection_secret,
                        std::unique_ptr<AuthAuthorizerChallenge> *challenge) override;

  int authorizer_session_crypto() override;
};

} // namespace university
} // namespace auth
} // namespace ceph
