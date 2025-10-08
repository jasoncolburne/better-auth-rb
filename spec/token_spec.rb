require 'spec_helper'
require_relative '../lib/better_auth/messages/access'
require_relative '../examples/crypto/secp256r1'
require_relative '../examples/encoding/token_encoder'

RSpec.describe 'Token parsing' do
  class MockAttributes
    attr_accessor :permissions_by_role

    def initialize(permissions_by_role = {})
      @permissions_by_role = permissions_by_role
    end

    def to_h
      { permissionsByRole: @permissions_by_role }
    end

    def to_json(*)
      to_h.to_json(*)
    end

    def self.from_hash(data)
      new(data[:permissionsByRole] || {})
    end
  end

  it 'can encode and decode tokens' do
    token_encoder = Examples::Encoding::TokenEncoder.new

    # rubocop:disable Layout/LineLength
    temp_token_string = '0IAGTf0y29Ra-8cjCnXS8NlImAi4_KZfaxgr_5iAux1CLoOZ7d5tvFktxb8Xc6pU2pYQkMw0V75fwP537N9dToIyH4sIAAAAAAACA22PXY-iMBSG_wvX203rUBHuOgIDasQ1jC5uNobaKkU-TFtAZ-J_nzoXu8nOnsuT93k_3i3FZc9lzHijhb5ZnoUIiUl_mNkp0isAWHpgCzKMWSaghJvE309VxifT6_no3Nh1G1jfLMZ7ceCGDYJhvIoDqXySVCAcPdfc2VFYlHG-TabDa0leu1NE56Byc8OJv6lB0taqqFx5jGadHfUiTU9OHYrFXp17FmKIdpfMZk80ileGvHS0Eoc5_1P4jVIM1qW92Qb-7keC6-HlxZH-Yjm-Coxilm1Q2-AV3dPO4LLVuRZtE-WqeISHIZDEGWe125Z-BnVHxc9NuQZk3c-XziyS5-2ybt6OpyJ51Faq44xoQ47gCAMEAZykaORh17PR9wnG8PN2RsuvFyFv_yifPGR_UUp-lFwVwRfATSH8n3WutRS001xZ3rt14bI2xcwo9XxbtxV_PHNWi8byfhnznBlkkEJz6_f9fv8A44o2TvkBAAA'
    # rubocop:enable Layout/LineLength

    temp_key = Examples::Crypto::Secp256r1.new

    temp_token = BetterAuth::Messages::AccessToken.parse(temp_token_string, token_encoder)
    new_token = BetterAuth::Messages::AccessToken.new(
      server_identity: temp_token.server_identity,
      device: temp_token.device,
      identity: temp_token.identity,
      public_key: temp_token.public_key,
      rotation_hash: temp_token.rotation_hash,
      issued_at: temp_token.issued_at,
      expiry: temp_token.expiry,
      refresh_expiry: temp_token.refresh_expiry,
      attributes: temp_token.attributes
    )

    new_token.sign(temp_key)
    token_string = new_token.serialize_token(token_encoder)

    token = BetterAuth::Messages::AccessToken.parse(token_string, token_encoder)

    expect(token.server_identity).to eq('1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE')
    expect(token.device).to eq('EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a')
    expect(token.identity).to eq('EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP')
    expect(token.public_key).to eq('1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu')
    expect(token.rotation_hash).to eq('EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO')
    expect(token.issued_at).to eq('2025-10-08T12:59:41.855000000Z')
    expect(token.expiry).to eq('2025-10-08T13:14:41.855000000Z')
    expect(token.refresh_expiry).to eq('2025-10-09T00:59:41.855000000Z')
    expect(token.attributes).to eq({ permissionsByRole: { admin: %w[read write] } })
  end
end
