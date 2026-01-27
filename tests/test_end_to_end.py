import roughly
import roughly.server


def test_server_and_client() -> None:
    server = roughly.server.Server.create()
    public_key = server.long_term_key.public_key().public_bytes_raw()

    p = roughly.build_request()
    payload = p.dump()

    raw_response = roughly.server.handle_request(server, payload)

    assert raw_response is not None

    response = roughly.Response.from_packet(raw=raw_response, request=payload)
    response.verify(public_key)
