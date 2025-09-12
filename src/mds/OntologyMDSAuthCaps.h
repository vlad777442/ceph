#pragma once

#include "mds/MDSAuthCaps.h"
#include "include/str_map.h"
#include <vector>
#include <string>
#include <map>

namespace ceph {
namespace ontology {

// Research data classification
enum class DataClassification {
  PUBLIC,
  INTERNAL,
  CONFIDENTIAL,
  RESTRICTED
};

// Research domain categories
enum class ResearchDomain {
  COMPUTER_SCIENCE,
  BIOLOGY,
  CHEMISTRY,
  PHYSICS,
  MATHEMATICS,
  MEDICINE,
  SOCIAL_SCIENCE,
  INTERDISCIPLINARY
};

// Ontology-aware capability specification
struct OntologyCapSpec : public MDSCapSpec {
  std::vector<ResearchDomain> allowed_domains;
  std::vector<std::string> allowed_projects;
  std::vector<std::string> allowed_collaborations;
  DataClassification max_data_classification;
  std::map<std::string, std::string> ontology_attributes;
  
  OntologyCapSpec() : MDSCapSpec() {}
  OntologyCapSpec(unsigned caps) : MDSCapSpec(caps) {}
  
  // Check if user can access based on research domain
  bool allows_domain(ResearchDomain domain) const;
  
  // Check if user can access specific project data
  bool allows_project(const std::string& project_id) const;
  
  // Check if user can access data at classification level
  bool allows_classification(DataClassification level) const;
  
  // Check ontology-specific attributes
  bool satisfies_ontology_constraints(const std::map<std::string, std::string>& user_attrs) const;
};

// Ontology-aware match conditions
struct OntologyCapMatch : public MDSCapMatch {
  std::vector<ResearchDomain> required_domains;
  std::vector<std::string> required_projects;
  std::string dataset_classification;
  std::map<std::string, std::string> required_attributes;
  
  // Check if path represents research data with specific classification
  bool matches_data_classification(const std::string& path) const;
  
  // Check if path belongs to accessible research domain
  bool matches_research_domain(const std::string& path, ResearchDomain domain) const;
  
  // Check if path belongs to accessible project
  bool matches_project(const std::string& path, const std::string& project_id) const;
  
  // Override base match to include ontology checks
  bool match_path(const std::string& path, const std::map<std::string, std::string>& context) const;
};

// Ontology-aware grant
struct OntologyCapGrant : public MDSCapGrant {
  OntologyCapSpec ontology_spec;
  OntologyCapMatch ontology_match;
  
  OntologyCapGrant() = default;
  OntologyCapGrant(const OntologyCapSpec& spec, const OntologyCapMatch& match)
    : ontology_spec(spec), ontology_match(match) {}
};

// Extended MDS capabilities with ontology awareness
class OntologyMDSAuthCaps : public MDSAuthCaps {
private:
  std::vector<OntologyCapGrant> ontology_grants;
  
public:
  OntologyMDSAuthCaps() = default;
  
  // Parse ontology-enhanced capability string
  bool parse_ontology_caps(const std::string& caps_str, std::ostream* err);
  
  // Check capability with ontology context
  bool is_capable_ontology(const std::string& inode_path,
                          uid_t inode_uid, gid_t inode_gid,
                          unsigned inode_mode,
                          uid_t caller_uid, gid_t caller_gid,
                          const std::vector<uint64_t>* caller_gid_list,
                          unsigned mask,
                          uid_t new_uid, gid_t new_gid,
                          const entity_addr_t& addr,
                          const std::map<std::string, std::string>& ontology_context) const;
  
  // Check research project access
  bool can_access_project(const std::string& project_id,
                         const std::map<std::string, std::string>& user_context) const;
  
  // Check data classification access
  bool can_access_classification(DataClassification level,
                                const std::map<std::string, std::string>& user_context) const;
  
  // Generate capability string with ontology constraints
  std::string to_ontology_string() const;
  
  // Merge ontology capabilities
  bool merge_ontology_caps(const OntologyMDSAuthCaps& other_caps);
};

// Utility functions for ontology integration
class OntologyUtils {
public:
  // Parse research domain from string
  static ResearchDomain parse_research_domain(const std::string& domain_str);
  
  // Parse data classification from string
  static DataClassification parse_data_classification(const std::string& class_str);
  
  // Extract project ID from file path
  static std::string extract_project_id(const std::string& path);
  
  // Extract data classification from path metadata
  static DataClassification extract_data_classification(const std::string& path);
  
  // Build ontology context from university authentication
  static std::map<std::string, std::string> build_ontology_context(
    const std::string& university_id,
    const std::string& department,
    const std::string& role,
    const std::vector<std::string>& projects,
    const std::vector<std::string>& collaborations);
};

} // namespace ontology
} // namespace ceph
