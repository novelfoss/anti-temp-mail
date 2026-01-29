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
        
        # 0. Infrastructure Classification
        mx_providers = set()
        for mx in records.mx:
            if mx == '.' or self._is_brand_match(base_domain, mx): continue
            mx_ext = tldextract.extract(mx)
            mx_providers.add(f"{mx_ext.domain}.{mx_ext.suffix}")
        
        is_managed_routing = len(mx_providers) > 0
        is_major_provider = any(p in str(mx_providers).lower() for p in ScoringConfig.MAJOR_NS_PROVIDERS)
        is_self_hosted = any(self._is_brand_match(base_domain, mx) for mx in records.mx if mx != '.')

        score = 0
        reasons = []

        # 1. Structural Analysis
        score += self._analyze_naming_structure(extracted, reasons)
        
        # 2. DNS Infrastructure Analysis
        score += self._analyze_infrastructure(records, base_domain, reasons, is_managed_routing, is_self_hosted)
        
        # 3. Security Posture
        score += self._evaluate_security_posture(records, score, reasons, is_managed_routing, is_self_hosted)
        
        # 4. Managed & Professional Checks
        score += self._analyze_managed_patterns(records, extracted, base_domain, reasons, 
                                                is_managed_routing, is_major_provider, mx_providers, is_self_hosted)

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
        
        if not records.mx:
            return 0 
        elif '.' in records.mx:
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
                penalty = 2 if subnet_count >= 3 else 6
                score_delta += penalty
                reasons.append(f"Parked NS: {ns}")
                break

        if any(base_domain in mx for mx in records.mx if mx != '.'):
            # Already calculated as is_self_hosted, but keep reason text if needed, or rely on is_self_hosted in score.
            # Increasing penalty slightly for Self-hosted if it's already flagged.
            score_delta += 2
            reasons.append("Self-hosted MX")

        # Maturity Check (SOA Serial)
        if records.soa and records.soa[0] < 1000:
            # Major NS (Route53, Cloudflare) often have low serials by default. 
            # If it's a brand-matched domain, be lenient.
            penalty = 6 if is_managed_routing else 2
            score_delta += penalty
            reasons.append("Low infrastructure maturity (SOA < 1000)")
        elif records.soa and records.soa[0] < 10000:
            penalty = 4 if is_managed_routing else 1
            score_delta += penalty
            reasons.append("Minimal infrastructure maturity (SOA < 10k)")

        return score_delta

    def _evaluate_security_posture(self, records: DNSRecords, current_score: int, reasons: List[str], is_managed_routing: bool, is_self_hosted: bool) -> int:
        score_delta = 0
        
        has_dmarc, dmarc_policy = self._parse_dmarc(records.dmarc)
        has_spf, non_spf_count = self._parse_spf(records.txt)
        
        is_major_ns = any(any(p in ns.lower() for p in ScoringConfig.MAJOR_NS_PROVIDERS) for ns in records.ns)
        
        complexity = 0.0
        for r in reasons:
            if "Unusual naming" in r:
                try: complexity = float(r.split('(')[-1].strip(')'))
                except: pass
                break

        if has_dmarc:
            if dmarc_policy == 'none' and (current_score >= 5 or len(records.mx) < 2):
                score_delta += 2
                reasons.append("No DMARC enforcement (p=none)")
        else:
            # DMARC Penalty logic: Professional setups on major NS MUST have DMARC.
            # But we are more lenient if it's NOT a generic managed routing domain.
            penalty = 4 if not is_managed_routing else 6
            if is_major_ns and is_managed_routing:
                penalty = 7 if complexity > 2.0 else 6
                
            if len(records.subnets_16) >= 4:
                penalty -= 2
            
            # Further leniency if there's business verification
            if non_spf_count >= 1 and not is_managed_routing:
                penalty = max(1, penalty - 3)
                
            score_delta += penalty
            reasons.append("No DMARC policy")

        if not has_spf:
            score_delta += 5
            reasons.append("No SPF policy")

        # Bonuses
        if non_spf_count >= 1:
            bonus = 5 if non_spf_count >= 2 else 2
            if is_self_hosted: bonus = 0 # Disable bonus for self-hosted to capture advanced temp mail
            
            if bonus > 0:
                score_delta -= bonus
                reasons.append(f"Verified domain (Tags: {non_spf_count})")

        if len(records.txt) > 5:
            score_delta -= 3
            reasons.append("Enterprise record density")

        return score_delta

    def _analyze_managed_patterns(self, records: DNSRecords, extracted: Any, base_domain: str, reasons: List[str], 
                                  is_managed_routing: bool, is_major_provider: bool, mx_providers: Set[str], is_self_hosted: bool) -> int:
        score_delta = 0
        
        is_pseudo_diverse = is_managed_routing and len(mx_providers) == 1 and len(records.mx) > 2 and not is_major_provider
        
        if is_pseudo_diverse:
            score_delta += 5
            reasons.append(f"Pseudo-diverse infrastructure (Shared provider: {list(mx_providers)[0]})")
        
        if is_managed_routing:
            if len(records.subnets_16) < 3:
                score_delta += 2
                reasons.append("Redirected mail routing")

        has_dmarc, _ = self._parse_dmarc(records.dmarc)
        _, non_spf_count = self._parse_spf(records.txt)
        is_major_ns = any(any(p in ns.lower() for p in ScoringConfig.MAJOR_NS_PROVIDERS) for ns in records.ns)
        
        complexity = self._calculate_string_complexity(extracted.domain)
        is_budget_tld = any(extracted.suffix == t.strip('.') for t in ScoringConfig.BUDGET_TLDS)
        is_low_maturity = records.soa and records.soa[0] < 1000

        # 1. Managed Minimalism
        if is_managed_routing:
            minimalism_penalty = 8 if not is_major_provider else 4
            if not has_dmarc and len(records.txt) <= 1:
                score_delta += minimalism_penalty
                reasons.append("Minimalist managed routing (No security)")
            elif len(records.txt) <= (3 if is_major_ns else 2):
                if complexity > 2.0 or (is_budget_tld and non_spf_count == 0):
                    score_delta += 6
                    reasons.append(f"Lean managed routing on '{extracted.domain}'")
                elif is_major_ns and non_spf_count <= 1 and not is_major_provider:
                    score_delta += 5
                    reasons.append("Lean professional profile")

        # 2. Infrastructure Redundancy
        if len(records.mx) == 1 and len(records.mx_ips) <= 2:
            penalty = 1 if (is_major_ns or non_spf_count >= 1) else 4
            if is_self_hosted: penalty = 4 # High penalty for self-hosted single MX
            score_delta += penalty
            reasons.append("Single mail host")

        # 4. Purpose Singularity
        if is_managed_routing and len(records.txt) <= 2 and non_spf_count <= 1:
            # Trigger singularity on budget TLDs, missing DMARC, major NS, or extremely low maturity
            # EXCEPT if it's a major provider or brand match (legit privacy mail apps often look like this)
            if (is_budget_tld or not has_dmarc or is_major_ns or is_low_maturity) and not is_major_provider:
                score_delta += 6
                reasons.append("Purpose singularity (Mail-only footprint)")

        # 5. Global Scale Gating
        has_spf, _ = self._parse_spf(records.txt)
        is_enterprise_scale = (len(records.mx) >= 3 or len(records.mx_ips) >= 5) and len(records.subnets_16) >= 3
        is_pro_baseline = (len(records.mx) >= 2 or len(records.mx_ips) >= 2)

        if is_enterprise_scale and has_spf and not is_pseudo_diverse:
            # Reduction in penalty for low maturity if on major NS
            bonus = 0 if (is_low_maturity and not is_major_ns) else (10 if has_dmarc else 6)
            if bonus > 0:
                score_delta -= bonus
                reasons.append("Enterprise-scale security")
        elif is_pro_baseline and has_spf:
            baseline_trust = 3 if (has_dmarc or non_spf_count >= 1) else 1
            if (complexity > 3.0 or (is_budget_tld and complexity > 0.5)) and len(records.txt) <= 2:
                baseline_trust = 0
            if is_low_maturity and baseline_trust > 1: baseline_trust = 1
            if baseline_trust > 0:
                score_delta -= baseline_trust
                reasons.append("Professional baseline")

        return score_delta

    def _is_brand_match(self, domain: str, mx_host: str) -> bool:
        """Heuristic to check if MX host belongs to the same brand as domain."""
        mx_host = mx_host.lower()
        domain = domain.lower()
        if domain in mx_host: return True
        
        extracted = tldextract.extract(domain)
        d_brand = extracted.domain
        
        mx_extracted = tldextract.extract(mx_host)
        m_brand = mx_extracted.domain
        
        if d_brand in m_brand or m_brand in d_brand: return True
        
        # Common prefix match (e.g. tutamail -> tutanota)
        if len(d_brand) >= 4 and len(m_brand) >= 4:
            if d_brand[:4] == m_brand[:4]: return True
            
        return False

    def _parse_dmarc(self, records: List[str]) -> Tuple[bool, str]:
        for rec in records:
            rec_l = rec.lower()
            if rec_l.startswith('v=dmarc1'):
                policy = 'none'
                if 'p=quarantine' in rec_l or 'p=reject' in rec_l:
                    policy = 'strict'
                return True, policy
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
        if not mx_records or '.' in mx_records:
            return set()
        
        ips = set()
        futures = [self._executor.submit(self._get_ips, mx) for mx in mx_records]
        for f in futures:
            try:
                ips.update(f.result())
            except: pass
        return ips

    def _get_ips(self, host: str) -> Set[str]:
        try:
            return set(socket.gethostbyname_ex(host)[2])
        except (socket.gaierror, socket.timeout):
            return set()

    def _query_dns(self, qname: str, rdtype: str, retries: int = 2) -> List[str]:
        for i in range(retries + 1):
            try:
                answers = self._resolver.resolve(qname, rdtype)
                if rdtype == 'MX':
                    return [str(r.exchange).strip('.').lower() for r in answers]
                elif rdtype == 'SOA':
                    return [r.serial for r in answers]
                return [str(r).strip('"') for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                if i < retries:
                    continue
                return []
        return []

    def _calculate_string_complexity(self, text: str) -> float:
        if len(text) < 4: return 0.0
        vowels = set("aeiou")
        v_count = sum(1 for c in text if c in vowels)
        c_ratio = v_count / len(text)
        
        volatility = 0.0
        if c_ratio < 0.2 or c_ratio > 0.6: volatility += 2.0
        
        d_count = sum(1 for c in text if c.isdigit())
        if d_count > 0: volatility += (d_count / len(text)) * 10
        return volatility

    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
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
    test_domains = [
        "gmail.com"
    ]
    
    print(f"{'DOMAIN':<25} | {'RESULT':<15} | {'TIME'}")
    # print("-" * 50)
    for d in test_domains:
        start = time.time()
        res, reasons = detector.analyze(d)
        print(f"{d:<25} | {res:<15} | {time.time()-start:.2f}s")
        if res != "safe":
            for r in reasons:
                print(f"  - {r}")
