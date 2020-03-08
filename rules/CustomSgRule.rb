require 'cfn-nag/violation'
require 'cfn-nag/base_rule'

class CustomSgRule < CfnNag::BaseRule
  def rule_text
    'SG found with cidr open to world on ingress and port outside of 80 and 443' 
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'F888'
  end

  ##
  # This will behave slightly different than the legacy jq based rule which was
  # targeted against inline ingress only
  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_ingresses = security_group.ingresses.select do |ingress|
        violating_ingress(ingress)
      end

      !violating_ingresses.empty?
    end

    violating_ingresses = cfn_model.standalone_ingress.select do |standalone_ingress|
      #violating_ingress(standalone_ingress)
      return true
    end

    violating_security_groups.map(&:logical_resource_id) + violating_ingresses.map(&:logical_resource_id)
  end

end