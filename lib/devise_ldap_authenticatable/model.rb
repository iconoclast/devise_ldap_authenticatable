require 'devise_ldap_authenticatable/strategy'

module Devise
  module Models
    # LDAP Module, responsible for validating the user credentials via LDAP.
    #
    # Examples:
    #
    #    User.authenticate('email@test.com', 'password123')  # returns authenticated user or nil
    #    User.find(1).valid_password?('password123')         # returns true/false
    #
    module LdapAuthenticatable
      extend ActiveSupport::Concern

      included do
        attr_reader :current_password, :password
        attr_accessor :password_confirmation
      end

      def login_with
        self[::Devise.authentication_keys.first]
      end

      def reset_password!(new_password, new_password_confirmation)
        if new_password == new_password_confirmation && ::Devise.ldap_update_password
          Devise::LdapAdapter.update_password(login_with, new_password)
        end
        clear_reset_password_token if valid?
        save
      end

      def password=(new_password)
        @password = new_password
      end

      # Checks if a resource is valid upon authentication.
      def valid_ldap_authentication?(password)
        if Devise::LdapAdapter.valid_credentials?(login_with, password)
          return true
        else
          return false
        end
      end

      def ldap_groups
        Devise::LdapAdapter.get_groups(login_with)
      end

      def ldap_dn
        Devise::LdapAdapter.get_dn(login_with)
      end

      def ldap_user_attributes(password)
        Devise::LdapAdapter.get_user_attributes(login_with, password)
      end

      module ClassMethods
        # Authenticate a user based on configured attribute keys. Returns the
        # authenticated user if it's valid or nil.
        def authenticate_with_ldap(attributes={})
          @login_with = ::Devise.authentication_keys.first
          return nil unless attributes[@login_with].present?

          resource = scoped.where(@login_with => attributes[@login_with]).first

          if (resource.blank? and ::Devise.ldap_create_user)
            resource = new
            resource[@login_with] = attributes[@login_with]
            resource.password = attributes[:password]
          end

          return nil unless resource.try(:valid_ldap_authentication?, attributes[:password])

          if ::Devise.ldap_managed_attributes
            # update user attributes with latest info in ldap
            # ldap_managed_attributes is a hash that maps the ldap attribute names to your user model attribute names
            user_attrs = resource.ldap_user_attributes(attributes[:password])

            new_values = {}
            ::Devise.ldap_managed_attributes.each {|k,v| new_values[v] = user_attrs[k].first if user_attrs[k].any? }

            resource.update_attributes new_values if new_values.any?
          end

          resource.save if resource.new_record? || resource.changed?
          return resource
        end

        def update_with_password(resource)
          puts "UPDATE_WITH_PASSWORD: #{resource.inspect}"
        end

      end
    end
  end
end
