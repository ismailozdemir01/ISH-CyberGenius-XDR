from app.translator import TranslatorClient

def test_translator_configuration_defaults():
    client = TranslatorClient("https://example.test", "secret", "westeurope")
    assert client.endpoint == "https://example.test"
    assert client.region == "westeurope"
