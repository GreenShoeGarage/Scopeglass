"""Validated local search, evaluated before sorting and pagination."""
import datetime as dt
import ipaddress
import json
import re
import shlex

SORTS={'ip','name','port','service','newest','oldest','severity'}
FIELDS={'text','ip','net','port','service','protocol','type','tag','name','expected','verified','severity','age'}
LEVEL={'info':0,'low':1,'medium':2,'high':3,'critical':4}


def parse_query(query):
    if not isinstance(query,str) or len(query)>500:raise ValueError('Search is limited to 500 characters.')
    try: tokens=shlex.split(query)
    except ValueError:raise ValueError('Close the quotation marks in your search.')
    if len(tokens)>32:raise ValueError('Use at most 32 search terms.')
    parsed=[]
    for token in tokens:
        negate=token.startswith('-') and len(token)>1
        token=token[1:] if negate else token
        field,value=token.split(':',1) if ':' in token else ('text',token)
        field=field.lower();value=value.casefold()
        if field!='text' and field not in FIELDS:raise ValueError(f'Unknown filter “{field}”. Use the search help for supported filters.')
        if not value:raise ValueError(f'Enter a value for {field}.')
        if field=='port':
            match=re.fullmatch(r'(\d+)(?:-(\d+))?',value)
            if not match:raise ValueError('Use port:23 or port:8000-8010.')
            value=(int(match[1]),int(match[2] or match[1]))
            if not 1<=value[0]<=value[1]<=65535:raise ValueError('Port filters must be between 1 and 65535.')
        elif field in ('ip','net'):
            try:value=ipaddress.IPv4Network(value,strict=False)
            except ValueError:raise ValueError('Use an IPv4 address or CIDR for ip/net filters.')
        elif field in ('expected','verified'):
            if value not in ('true','false'):raise ValueError(f'{field} accepts true or false.')
            value=value=='true'
        elif field=='severity':
            if value not in LEVEL:raise ValueError('Severity accepts info, low, medium, high, or critical.')
        elif field=='type':
            if value not in ('camera','streaming','unknown'):raise ValueError('Type accepts camera, streaming, or unknown.')
        elif field=='age':
            match=re.fullmatch(r'([<>]=?)(\d+)([mhd])',value)
            if not match:raise ValueError('Use age:>7d, age:<=24h, or age:<30m.')
            value=(match[1],int(match[2])*{'m':60,'h':3600,'d':86400}[match[3]])
        parsed.append((field,value,negate))
    return parsed


def observed_age(observed,reference):
    try:
        moment=dt.datetime.fromisoformat(observed.replace('Z','+00:00'))
        if moment.tzinfo is None:moment=moment.replace(tzinfo=dt.timezone.utc)
        return max(0,(reference-moment).total_seconds())
    except (ValueError,TypeError,AttributeError):return None


def matches(item,asset,terms,reference):
    meta=item.get('metadata',{})
    protocol=meta.get('protocol','unknown')
    verified=meta.get('identification')=='verified'
    for field,value,negate in terms:
        if field=='text':
            found=value in (' '.join(str(item[k]) for k in ('host','port','service','banner'))+' '+json.dumps(meta,ensure_ascii=False)+' '+' '.join([asset.get('name',''),asset.get('notes',''),*asset.get('tags',[])])).casefold()
        elif field in ('ip','net'):found=ipaddress.ip_address(item['host']) in value
        elif field=='port':found=value[0]<=item['port']<=value[1]
        elif field=='protocol':found=verified and protocol==value
        elif field=='service':found=(protocol if verified else item['service']).casefold()==value
        elif field=='type':found=meta.get('device',{}).get('kind','unknown')==value
        elif field=='tag':found=value in [t.casefold() for t in asset['tags']]
        elif field=='name':found=value in asset['name'].casefold()
        elif field=='expected':found=item['expected']==value
        elif field=='verified':found=verified==value
        elif field=='severity':found=any(f['severity']==value for f in item['findings'])
        else:
            seconds=observed_age(item['observed'],reference)
            op,threshold=value
            found=seconds is not None and {'>':lambda:seconds>threshold,'>=':lambda:seconds>=threshold,'<':lambda:seconds<threshold,'<=':lambda:seconds<=threshold}[op]()
        if found==negate:return False
    return True


def sort_items(items,assets,sort):
    if sort not in SORTS:raise ValueError('Unknown sort order.')
    def key(item):
        base=(int(ipaddress.ip_address(item['host'])),item['port'])
        if sort=='ip':return base
        if sort=='name':return (assets[item['host']]['name'].casefold() or item['host'],*base)
        if sort=='port':return (item['port'],*base)
        if sort=='service':return (item['metadata'].get('protocol') if item['metadata'].get('identification')=='verified' else item['service'],*base)
        if sort=='severity':return (-max((LEVEL.get(f['severity'],0) for f in item['findings']),default=-1),*base)
        try:
            moment=dt.datetime.fromisoformat(item['observed'].replace('Z','+00:00'))
            if moment.tzinfo is None:moment=moment.replace(tzinfo=dt.timezone.utc)
            stamp=moment.timestamp()
        except (ValueError,TypeError,AttributeError):stamp=0
        return ((-stamp if sort=='newest' else stamp),*base)
    return sorted(items,key=key)
