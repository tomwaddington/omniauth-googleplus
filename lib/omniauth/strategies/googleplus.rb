require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class GooglePlus < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = "userinfo.email,plus.login"
      

      option :name, 'googleplus'
      option :authorize_options, [:scope, :approval_prompt, :access_type, :state, :hd]

      option :client_options, {
        :site          => 'https://accounts.google.com',
        :authorize_url => '/o/oauth2/auth',
        :token_url     => '/o/oauth2/token'
      }

      def authorize_params
        base_scope_url = "https://www.googleapis.com/auth/"
        
        super.tap do |params|
          # Read the params if passed directly to omniauth_authorize_path
          %w(scope approval_prompt access_type state hd user_id request_visible_actions).each do |k|
            params[k.to_sym] = request.params[k] unless [nil, ''].include?(request.params[k])
          end
          scopes = (params[:scope] || DEFAULT_SCOPE).split(",")
          scopes.map! { |s| s =~ /^https?:\/\// ? s : "#{base_scope_url}#{s}" }
          params[:scope] = scopes.join(' ')

          # Override the state per request
          session['omniauth.state'] = params[:state] if request.params['state']
        end
      end

      uid{ raw_info['id'] || verified_email }

      info do
        prune!({
          :name       => [raw_info['name']['given_name'], raw_info['name']['family_name']].join(' '),
          :email      => verified_email,
          :first_name => raw_info['name']['given_name'],
          :last_name  => raw_info['name']['family_name'],
          :image      => raw_info['image']['url'],
          :urls => {
            'Google' => raw_info['link']
          }
        })
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      def email_info
        @email_info ||= access_token.get('https://www.googleapis.com/oauth2/v1/tokeninfo').parsed
        
      end

      def raw_info
        #GET https://www.googleapis.com/plus/v1/people/userId
        @raw_info ||= access_token.get('https://www.googleapis.com/plus/v1/people/me').parsed
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def verified_email
        email_info['verified_email'] ? email_info['email'] : nil
      end

    end
  end
end
