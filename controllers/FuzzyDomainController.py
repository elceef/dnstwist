from flask_api import status
from flask_restful import Resource

from dnstwist import UrlParser, DomainFuzz


class FuzzyDomainsController(Resource):
    def get(self, domain):
        try:
            url = UrlParser(domain)
        except ValueError as err:
            return err, status.HTTP_400_BAD_REQUEST

        domain_fuzz = DomainFuzz(url.domain)
        domain_fuzz.generate()

        result = {
            "domain": domain_fuzz.domain,
            "fuzzy_domains": domain_fuzz.domains
        }

        return result, status.HTTP_200_OK
