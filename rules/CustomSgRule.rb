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
    'F899'
  end

  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_ingresses = security_group.ingresses.select do |ingress|
        violating_ingress(ingress)
      end

      !violating_ingresses.empty?
    end

    violating_ingresses = cfn_model.standalone_ingress.select do |standalone_ingress|
      violating_ingress(standalone_ingress)
    end

    violating_security_groups.map(&:logical_resource_id) + violating_ingresses.map(&:logical_resource_id)
  end

  def violating_ingress(ingress)
    if (ingress.fromPort.to_i != 80 && ingress.toPort.to_i != 80) &&
        (ingress.fromPort.to_i != 443 && ingress.toPort.to_i != 443) &&
        (ingress.cidrIp == '0.0.0.0/0')
        return true
    else
        return false
    end
  end

end