require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Globalize < OmniAuth::Strategies::OAuth2

      if defined?(Rails) and %w(test development dev).include?(Rails.env.to_s)
        option :client_options, {
            :site => 'http://globalize.lvh.me:3030/api/v1',
            :authorize_url => 'http://globalize.lvh.me:3030/oauth/authorize',
            :token_url => 'http://globalize.lvh.me:3030/oauth/token'
        }
      else
        option :client_options, {
            :site => 'https://globalize.io/api/v1',
            :authorize_url => 'https://globalize.io/oauth/authorize',
            :token_url => 'https://globalize.io/oauth/token'
        }
      end

      option :name, 'globalize'

      option :access_token_options, {
          :header_format => 'OAuth %s',
          :param_name => 'access_token'
      }

      option :authorize_options, [:scope, :display]

      def request_phase
        super
      end

      uid { raw_info['id'] }

      info do
        prune!({
                   'id' => raw_info['id'],
                   'name' => raw_info['name'],
                   'email' => raw_info['email']
               })
      end

      extra do
        {'user' => prune!(raw_info)}
      end

      def raw_info
        @raw_info ||= access_token.get('users/me').parsed
      end

      def authorize_params
        super.tap do |params|
          params.merge!(:display => request.params['display']) if request.params['display']
          params.merge!(:state => request.params['state']) if request.params['state']
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

    end
  end
end

OmniAuth.config.add_camelization 'globalize', 'Globalize'
