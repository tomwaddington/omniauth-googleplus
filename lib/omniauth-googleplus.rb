require "omniauth-oauth2"
require_relative "omniauth/strategies/googleplus"
require_relative "omniauth/googleplus/version"

OmniAuth.config.add_camelization("googleplus", "GooglePlus")
