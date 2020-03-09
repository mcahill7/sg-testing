require 'spec_helper'
require 'cfn-model'
require 'cfn-nag/custom_rules/ARule'

describe ARule do

  context 'dangling security group ingress rules open to port range' do
    it 'returns offending logical resource id' do
      cfn_model = CfnParser.new.parse read_test_template('json/security_group/sg1.json')

      actual_logical_resource_ids = ARule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[sgOpenIngress sgOpenIngress2]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end

    it 'returns offending logical resource id123' do
      cfn_model = CfnParser.new.parse read_test_template('json/security_group/sg2.json')

      actual_logical_resource_ids = ARule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[sgOpenIngress sgOpenIngress3 sgOpenIngress4 sgOpenIngress2]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end

    it 'returns offending logical resource 12312235' do
      cfn_model = CfnParser.new.parse read_test_template('yaml/security_group/sg3.yaml')

      actual_logical_resource_ids = ARule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[WideOpenSecurityGroup]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
