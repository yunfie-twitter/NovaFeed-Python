import base64
import secrets
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from django.conf import settings
import logging
import json
logger = logging.getLogger(__name__)


def get_registration_options(user):
    """
    パスキー登録用のオプションを生成
    """
    try:
        # チャレンジを生成
        challenge = secrets.token_bytes(32)
        
        # ユーザー情報
        user_id = str(user.id).encode('utf-8')
        user_name = user.username
        user_display_name = user.get_display_name()
        
        logger.info(f"RP ID: {settings.WEBAUTHN_RP_ID}")
        logger.info(f"RP Name: {settings.WEBAUTHN_RP_NAME}")
        logger.info(f"User: {user_name} ({user_display_name})")
        
        # 登録オプションを生成
        options = generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_id=user_id,
            user_name=user_name,
            user_display_name=user_display_name,
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        
        # Base64URLエンコード用のヘルパー関数
        def bytes_to_base64url(data):
            return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
        
        # チャレンジをBase64URLエンコード
        challenge_b64 = bytes_to_base64url(challenge)
        
        logger.info(f"Registration options generated for user: {user.username}")
        
        return {
            'options': options,
            'challenge': challenge_b64,
        }
        
    except Exception as e:
        logger.error(f"Error generating registration options: {e}")
        import traceback
        traceback.print_exc()
        raise


def verify_registration(user, credential_data, challenge):
    """
    パスキー登録のレスポンスを検証
    """
    try:
        # チャレンジをデコード
        challenge_padding = '=' * (4 - len(challenge) % 4)
        expected_challenge = base64.urlsafe_b64decode(challenge + challenge_padding)
        
        # credential_dataを適切な形式に変換
        # rawIdをバイナリに変換
        raw_id_padding = '=' * (4 - len(credential_data['rawId']) % 4)
        raw_id_bytes = base64.urlsafe_b64decode(
            credential_data['rawId'].replace('-', '+').replace('_', '/') + raw_id_padding
        )
        
        # clientDataJSONをバイナリに変換
        client_data_padding = '=' * (4 - len(credential_data['response']['clientDataJSON']) % 4)
        client_data_json = base64.urlsafe_b64decode(
            credential_data['response']['clientDataJSON'].replace('-', '+').replace('_', '/') + client_data_padding
        )
        
        # attestationObjectをバイナリに変換
        attestation_padding = '=' * (4 - len(credential_data['response']['attestationObject']) % 4)
        attestation_object = base64.urlsafe_b64decode(
            credential_data['response']['attestationObject'].replace('-', '+').replace('_', '/') + attestation_padding
        )
        
        logger.info(f"Verifying registration for user: {user.username}")
        logger.info(f"Expected challenge length: {len(expected_challenge)}")
        logger.info(f"Raw ID length: {len(raw_id_bytes)}")
        
        # 検証用のデータを準備
        from webauthn.helpers import parse_registration_credential_json
        
        # JSON形式に変換
        credential_json = {
            "id": credential_data['id'],
            "rawId": credential_data['rawId'],
            "type": credential_data['type'],
            "response": {
                "clientDataJSON": credential_data['response']['clientDataJSON'],
                "attestationObject": credential_data['response']['attestationObject'],
            }
        }
        
        import json
        credential_json_str = json.dumps(credential_json)
        parsed_credential = parse_registration_credential_json(credential_json_str)
        
        # 検証
        verification = verify_registration_response(
            credential=parsed_credential,
            expected_challenge=expected_challenge,
            expected_origin=settings.WEBAUTHN_ALLOWED_ORIGINS[0],
            expected_rp_id=settings.WEBAUTHN_RP_ID,
        )
        
        logger.info(f"Registration verified for user: {user.username}")
        
        # credential_idとpublic_keyをBase64URLエンコード
        credential_id_b64 = base64.urlsafe_b64encode(verification.credential_id).decode('utf-8').rstrip('=')
        public_key_b64 = base64.urlsafe_b64encode(verification.credential_public_key).decode('utf-8').rstrip('=')
        
        # aaguidの処理を修正
        aaguid_hex = None
        if hasattr(verification, 'aaguid') and verification.aaguid:
            if isinstance(verification.aaguid, bytes):
                aaguid_hex = verification.aaguid.hex()
            elif isinstance(verification.aaguid, str):
                aaguid_hex = verification.aaguid
        
        return {
            'credential_id': credential_id_b64,
            'public_key': public_key_b64,
            'sign_count': verification.sign_count,
            'aaguid': aaguid_hex,
        }
        
    except Exception as e:
        logger.error(f"Error verifying registration: {e}")
        import traceback
        traceback.print_exc()
        raise


def get_authentication_options(user, credentials):
    """
    パスキー認証用のオプションを生成
    """
    try:
        # チャレンジを生成
        challenge = secrets.token_bytes(32)
        
        # 登録済みの認証情報リスト
        allow_credentials = []
        for cred in credentials:
            credential_id_padding = '=' * (4 - len(cred.credential_id) % 4)
            credential_id = base64.urlsafe_b64decode(cred.credential_id + credential_id_padding)
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=credential_id
                )
            )
        
        # 認証オプションを生成
        options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            challenge=challenge,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        logger.info(f"Authentication options generated for user: {user.username}")
        
        return {
            'options': options,
            'challenge': base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('='),
        }
        
    except Exception as e:
        logger.error(f"Error generating authentication options: {e}")
        import traceback
        traceback.print_exc()
        raise


def verify_authentication(user, credential_data, challenge, stored_credential):
    """
    パスキー認証のレスポンスを検証
    """
    try:
        import base64
        
        # Base64URLデコード用のヘルパー関数（改良版）
        def safe_b64decode(data):
            """安全なBase64URLデコード"""
            try:
                # まずはそのまま試す
                return base64.urlsafe_b64decode(data)
            except Exception:
                # パディングを追加して再試行
                padding = 4 - (len(data) % 4)
                if padding and padding != 4:
                    data_padded = data + ('=' * padding)
                    return base64.urlsafe_b64decode(data_padded)
                raise
        
        # チャレンジをデコード
        try:
            expected_challenge = safe_b64decode(challenge)
            logger.info(f"Challenge decoded successfully, length: {len(expected_challenge)}")
        except Exception as e:
            logger.error(f"Challenge decode error: {e}, challenge: {challenge}")
            raise
        
        # 公開鍵をデコード
        try:
            credential_public_key = safe_b64decode(stored_credential.public_key)
            logger.info(f"Public key decoded successfully, length: {len(credential_public_key)}")
        except Exception as e:
            logger.error(f"Public key decode error: {e}")
            raise
        
        # credential_idをデコード
        try:
            credential_id = safe_b64decode(stored_credential.credential_id)
            logger.info(f"Credential ID decoded successfully, length: {len(credential_id)}")
        except Exception as e:
            logger.error(f"Credential ID decode error: {e}")
            raise
        
        # JSON形式に変換
        from webauthn.helpers import parse_authentication_credential_json
        
        credential_json = {
            "id": credential_data['id'],
            "rawId": credential_data['rawId'],
            "type": credential_data['type'],
            "response": {
                "clientDataJSON": credential_data['response']['clientDataJSON'],
                "authenticatorData": credential_data['response']['authenticatorData'],
                "signature": credential_data['response']['signature'],
            }
        }
        
        if 'userHandle' in credential_data.get('response', {}):
            credential_json['response']['userHandle'] = credential_data['response']['userHandle']
        
        credential_json_str = json.dumps(credential_json)
        logger.info(f"Credential JSON prepared")
        
        parsed_credential = parse_authentication_credential_json(credential_json_str)
        logger.info(f"Credential parsed successfully")
        
        # 検証
        verification = verify_authentication_response(
            credential=parsed_credential,
            expected_challenge=expected_challenge,
            expected_origin=settings.WEBAUTHN_ALLOWED_ORIGINS[0],
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            credential_public_key=credential_public_key,
            credential_current_sign_count=stored_credential.sign_count,
        )
        
        logger.info(f"Authentication verified for user: {user.username}")
        
        return {
            'verified': True,
            'new_sign_count': verification.new_sign_count,
        }
        
    except Exception as e:
        logger.error(f"Error verifying authentication: {e}")
        import traceback
        traceback.print_exc()
        raise
