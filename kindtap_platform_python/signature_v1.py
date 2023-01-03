import hashlib
import hmac
import logging
import re
from urllib.parse import quote


ALGO_PRE = 'KT1'
ALGO = f'{ALGO_PRE}-HMAC-SHA256'
AUTH_TYPE = f'{ALGO_PRE.lower()}_request'
REGION = 'us'

EQUALS_EXPR = re.compile('=')
EQUALS_ENC = quote('=')
MULTI_WS_EXPR = re.compile('[ ][ ]+')


logger = logging.getLogger()


def _build_canon_headers(headers):
    headers_pre = map(lambda i: (i[0].lower(), i[1]), headers.items())
    headers_sorted = sorted(headers_pre, key=lambda i: ord(i[0][0]))
    headers_post = []
    for k, v in headers_sorted:
        v_post = re.sub(MULTI_WS_EXPR, ' ', (v or '').strip())
        headers_post.append(f'{k}:{v_post}')
    return '\n'.join(headers_post) + '\n'


def _build_canon_query(params):
    params_sorted = sorted(list(params.items()), key=lambda i: ord(i[0][0]))
    params_enc = []
    for k, v in params_sorted:
        k_enc = quote(k)
        v_enc = quote(re.sub(EQUALS_EXPR, EQUALS_ENC, v or ''))
        params_enc.append(f'{k_enc}={v_enc}')
    return '&'.join(params_enc)


def _build_canon_uri(uri):
    path_parts = list(filter(None, uri.split('/')))
    if len(path_parts) == 0:
        return '/'
    return '/' + '/'.join(map(lambda p: quote(quote(p, safe="")), path_parts)) + '/'


def _build_signed_headers(headers):
    headers_pre = map(lambda i: i[0].lower(), headers.items())
    headers_sorted = sorted(headers_pre, key=lambda i: ord(i[0]))
    return ';'.join(headers_sorted)


def generate_signature_v1(
    service,
    client_secret,
    req_method,
    req_uri,
    req_date,
    req_headers,
    req_body,
    req_params,
):
    canon_headers = _build_canon_headers(req_headers)
    canon_query = _build_canon_query(req_params)
    canon_uri = _build_canon_uri(req_uri)
    signed_headers = _build_signed_headers(req_headers)

    if isinstance(req_body, bytes):
        body_bytes = req_body
    else:
        body_bytes = bytes(req_body, 'utf-8')

    canon_request = '\n'.join([
        req_method.upper(),
        canon_uri,
        canon_query,
        canon_headers,
        signed_headers,
        hashlib.sha256(body_bytes).hexdigest(),
    ])
    logger.debug(f'Canonical Request: {canon_request}')
    canon_request_hash = hashlib.sha256(bytes(canon_request, 'utf-8')).hexdigest()
    logger.debug(f'Canonical Request Hash: {canon_request_hash}')

    cred_date = stringify_date(req_date)
    cred_scope = f'{cred_date}/{REGION}/{service}/{AUTH_TYPE}'

    msg_to_sign = '\n'.join([
        ALGO,
        stringify_date(req_date, True),
        cred_scope,
        canon_request_hash,
    ])
    logger.debug(f'Message to Sign: {msg_to_sign}')

    key0 = hmac.new(bytes(f'{ALGO_PRE}{client_secret}', 'utf-8'), bytes(cred_date, 'utf-8'), hashlib.sha256)
    key1 = hmac.new(key0.digest(), bytes(REGION, 'utf-8'), hashlib.sha256)
    key2 = hmac.new(key1.digest(), bytes(service, 'utf-8'), hashlib.sha256)
    key3 = hmac.new(key2.digest(), bytes(AUTH_TYPE, 'utf-8'), hashlib.sha256)

    signature = hmac.new(key3.digest(), bytes(msg_to_sign, 'utf-8'), hashlib.sha256).hexdigest()
    logger.debug(f'Signature: {signature}')

    return signature


def generate_signed_auth_header(
    service,
    client_key,
    client_secret,
    req_method,
    req_uri,
    req_date,
    req_headers,
    req_body,
    req_params,
):
    cred_date = stringify_date(req_date)
    cred_scope = f'{cred_date}/{REGION}/{service}/{AUTH_TYPE}'

    signed_headers = _build_signed_headers(req_headers)

    signature = generate_signature_v1(
        service,
        client_secret,
        req_method,
        req_uri,
        req_date,
        req_headers,
        req_body,
        req_params,
    )

    auth = f'{ALGO} Credential={client_key}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}'
    logger.debug(f'Authorization: {auth}')

    return auth


def stringify_date(d, t=False):
    if t:
        return d.strftime('%Y%m%dT%H%M%SZ')
    return d.strftime('%Y%m%d')
