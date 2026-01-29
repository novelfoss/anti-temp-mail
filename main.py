import math
import socket
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional, Set, Any
from dataclasses import dataclass

import dns.resolver
import tldextract

@dataclass
class DNSRecords:
    mx: List[str]
    txt: List[str]
    dmarc: List[str]
    ns: List[str]
    soa: List[int]
    mx_ips: Set[str] = None
    subnets_16: Set[str] = None

class ScoringConfig:
    MAJOR_NS_PROVIDERS = {
        'cloudflare.com', 'awsdns', 'google.com', 'googledomains', 
        'azure-dns', 'digitalocean.com', 'linode.com', 'vultr.com', 
        'namecheap.com', 'porkbun.com', 'registrar-servers.com'
    }
    
    PARKED_NS_KEYWORDS = {'park', 'parking', 'bodis', 'sedo', 'dns-parking'}
    BUDGET_TLDS = {
        '.top', '.site', '.live', '.xyz', '.casa', '.pw', '.dev', '.today', 
        '.xxx', '.club', '.online', '.shop', '.store', '.vip', '.cc'
    }
    
    TEMP_MAIL_THRESHOLD = 6
    ALIAS_THRESHOLD = 1
    
    VERIFICATION_TAGS = {'verify', 'verification', 'site-verification', 'key', 'abuseipdb'}

class EmailDetector:
    def __init__(self, max_workers: int = 20):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._resolver = dns.resolver.Resolver()

        self._resolver.nameservers = [
            "8.8.8.8",   # Google DNS
            "1.1.1.1"    # Cloudflare DNS
        ]

        self._resolver.timeout = 3.0
        self._resolver.lifetime = 3.0

    @lru_cache(maxsize=2048)
    def analyze(self, email_or_domain: str) -> Tuple[str, List[str]]:
        domain = self._extract_domain(email_or_domain)
        if not domain:
            return "invalid", ["Invalid domain format"]

        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        records = self._resolve_dns_records(domain)
        
        if not records.mx:
            return "invalid", ["No MX records found"]
        if '.' in records.mx and len(records.mx) == 1:
            return "invalid", ["Explicit Null MX record identified"]
        
        mx_providers = set()
        for mx in records.mx:
            if mx == '.' or self._is_brand_match(base_domain, mx):
                continue
            mx_ext = tldextract.extract(mx)
            mx_providers.add(f"{mx_ext.domain}.{mx_ext.suffix}")
        
        is_managed_routing = len(mx_providers) > 0
        is_major_provider = any(p in str(mx_providers).lower() for p in ScoringConfig.MAJOR_NS_PROVIDERS)
        is_self_hosted = any(self._is_brand_match(base_domain, mx) for mx in records.mx if mx != '.')

        score = 0
        reasons = []

        score += self._analyze_naming_structure(extracted, reasons)
        score += self._analyze_infrastructure(records, base_domain, reasons, is_managed_routing, is_self_hosted)
        score += self._evaluate_security_posture(records, score, reasons, is_managed_routing, is_self_hosted)
        score += self._analyze_managed_patterns(
            records, extracted, base_domain, reasons,
            is_managed_routing, is_major_provider, mx_providers, is_self_hosted
        )

        return self._classify(score, reasons)

    def _extract_domain(self, input_str: str) -> Optional[str]:
        if '@' in input_str:
            return input_str.split('@')[-1].lower()
        return input_str.lower()

    def _resolve_dns_records(self, domain: str) -> DNSRecords:
        lookups = {
            'mx': self._executor.submit(self._query_dns, domain, 'MX'),
            'txt': self._executor.submit(self._query_dns, domain, 'TXT'),
            'dmarc': self._executor.submit(self._query_dns, f"_dmarc.{domain}", 'TXT'),
            'ns': self._executor.submit(self._query_dns, domain, 'NS'),
            'soa': self._executor.submit(self._query_dns, domain, 'SOA'),
        }

        records = DNSRecords(
            mx=lookups['mx'].result(),
            txt=lookups['txt'].result(),
            dmarc=lookups['dmarc'].result(),
            ns=lookups['ns'].result(),
            soa=lookups['soa'].result()
        )
        
        records.mx_ips = self._resolve_mx_ips(records.mx)
        records.subnets_16 = {'.'.join(ip.split('.')[:2]) for ip in records.mx_ips}
        
        return records

    def _analyze_naming_structure(self, extracted: Any, reasons: List[str]) -> int:
        score_delta = 0
        
        complexity = self._calculate_string_complexity(extracted.domain)
        if complexity > 3.0:
            score_delta += 5
            reasons.append(f"Unusual naming ({complexity:.1f})")

        if extracted.domain.count('-') >= 2:
            score_delta += 3
            reasons.append("High hyphenation frequency")

        is_budget = any(extracted.suffix == t.strip('.') for t in ScoringConfig.BUDGET_TLDS)
        if is_budget:
            score_delta += 2
            reasons.append(f"Budget TLD (.{extracted.suffix})")

        if extracted.subdomain:
            score_delta += 5
            reasons.append(f"Redirected subdomain: {extracted.subdomain}")

        entropy = self._calculate_entropy(extracted.domain)
        if entropy > 4.2 and len(extracted.domain) > 10:
            score_delta += 5
            reasons.append(f"High naming entropy: {entropy:.2f}")

        return score_delta

    def _analyze_infrastructure(self, records: DNSRecords, base_domain: str, reasons: List[str], is_managed_routing: bool, is_self_hosted: bool) -> int:
        score_delta = 0
        
        if not records.mx or '.' in records.mx:
            return 0 

        subnet_count = len(records.subnets_16)
        if subnet_count >= 5:
            score_delta -= 7
            reasons.append(f"Wide IP diversity ({subnet_count} subnets)")
        elif subnet_count >= 3:
            score_delta -= 4
            reasons.append(f"Global IP diversity ({subnet_count} subnets)")

        is_major_ns = any(any(p in ns.lower() for p in ScoringConfig.MAJOR_NS_PROVIDERS) for ns in records.ns)
        if is_major_ns and not is_self_hosted:
            score_delta -= 2
            reasons.append("Common NS infrastructure") 

        for ns in records.ns:
            if any(k in ns.lower() for k in ScoringConfig.PARKED_NS_KEYWORDS):
                score_delta += 6
                reasons.append(f"Parked NS: {ns}")
                break

        if records.soa and records.soa[0] < 1000:
            score_delta += 6
            reasons.append("Low infrastructure maturity (SOA < 1000)")

        return score_delta

    def _evaluate_security_posture(self, records: DNSRecords, current_score: int, reasons: List[str], is_managed_routing: bool, is_self_hosted: bool) -> int:
        score_delta = 0
        
        has_dmarc, _ = self._parse_dmarc(records.dmarc)
        has_spf, non_spf_count = self._parse_spf(records.txt)

        if not has_dmarc:
            score_delta += 6
            reasons.append("No DMARC policy")

        if not has_spf:
            score_delta += 5
            reasons.append("No SPF policy")

        if non_spf_count >= 1:
            score_delta -= 2
            reasons.append("Verified domain")

        return score_delta

    def _analyze_managed_patterns(self, records: DNSRecords, extracted: Any, base_domain: str, reasons: List[str], 
                                  is_managed_routing: bool, is_major_provider: bool, mx_providers: Set[str], is_self_hosted: bool) -> int:
        score_delta = 0

        if len(records.mx) == 1:
            score_delta += 4
            reasons.append("Single mail host")

        return score_delta

    def _is_brand_match(self, domain: str, mx_host: str) -> bool:
        mx_host = mx_host.lower()
        domain = domain.lower()
        return domain in mx_host

    def _parse_dmarc(self, records: List[str]) -> Tuple[bool, str]:
        for rec in records:
            rec_l = rec.lower()
            if rec_l.startswith('v=dmarc1'):
                return True, 'strict'
        return False, 'none'

    def _parse_spf(self, records: List[str]) -> Tuple[bool, int]:
        has_spf = False
        non_spf_count = 0
        for txt in records:
            txt_l = txt.lower()
            if 'v=spf1' in txt_l:
                has_spf = True
            elif any(word in txt_l for word in ScoringConfig.VERIFICATION_TAGS):
                non_spf_count += 1
        return has_spf, non_spf_count

    def _resolve_mx_ips(self, mx_records: List[str]) -> Set[str]:
        ips = set()
        for mx in mx_records:
            try:
                ips.update(socket.gethostbyname_ex(mx)[2])
            except:
                pass
        return ips

    def _query_dns(self, qname: str, rdtype: str) -> List[str]:
        try:
            answers = self._resolver.resolve(qname, rdtype)
            if rdtype == 'MX':
                return [str(r.exchange).strip('.').lower() for r in answers]
            elif rdtype == 'SOA':
                return [r.serial for r in answers]
            return [str(r).strip('"') for r in answers]
        except:
            return []

    def _calculate_string_complexity(self, text: str) -> float:
        if len(text) < 4:
            return 0.0
        vowels = set("aeiou")
        v_count = sum(1 for c in text if c in vowels)
        return abs(0.4 - (v_count / len(text))) * 10

    def _calculate_entropy(self, text: str) -> float:
        counts = {c: text.count(c) for c in set(text)}
        return sum(-(count/len(text)) * math.log2(count/len(text)) for count in counts.values())

    def _classify(self, score: int, reasons: List[str]) -> Tuple[str, List[str]]:
        if score >= ScoringConfig.TEMP_MAIL_THRESHOLD:
            return "temp-mail", reasons
        elif score >= ScoringConfig.ALIAS_THRESHOLD:
            return "privacy/alias", reasons
        return "safe", reasons

if __name__ == "__main__":
    import time
    detector = EmailDetector()
    for d in ["gmail.com"]:
        start = time.time()
        res, reasons = detector.analyze(d)
        print(d, res, time.time() - start)
        for r in reasons:
            print(" -", r)
