import re
from typing import Dict, Optional
try:
    from backend.models.stream import StreamMetadata
except ImportError:
    from models.stream import StreamMetadata

class SdpParser:
    @staticmethod
    def parse(sdp_text: str) -> StreamMetadata:
        """
        Parses SDP text and generates a StreamMetadata object.
        """
        meta = StreamMetadata(ssrc=0, src_ip="", dst_ip="", dst_port=5004)
        
        for line in sdp_text.splitlines():
            line = line.strip()
            if not line: continue
            
            if line.startswith("s="):
                meta.session_name = line[2:]
            elif line.startswith("c=IN IP4 "):
                # c=IN IP4 239.69.0.1/32
                parts = line.split()
                if len(parts) >= 3:
                    meta.dst_ip = parts[2].split('/')[0]
            elif line.startswith("m=audio "):
                # m=audio 5004 RTP/AVP 96
                parts = line.split()
                if len(parts) >= 2:
                    meta.dst_port = int(parts[1])
            elif line.startswith("a=rtpmap:"):
                # a=rtpmap:96 L24/48000/8
                match = re.match(r"a=rtpmap:(\d+) (\w+)/(\d+)(?:/(\d+))?", line)
                if match:
                    meta.payload_type = int(match.group(1))
                    meta.encoding = match.group(2).upper()  # RFC 4566: case-insensitive
                    meta.sample_rate = int(match.group(3))
                    meta.channels = int(match.group(4)) if match.group(4) else 1
            elif line.startswith("a=ptime:"):
                try: meta.ptime = float(line.split(":")[1])
                except: pass
            elif line.startswith("a=clock-domain:"):
                # a=clock-domain:PTPv2 0
                parts = line.split(":", 1)[1].split()
                if len(parts) >= 2:
                    try: meta.clock_domain = int(parts[1])
                    except: pass
            elif line.startswith("a=ts-refclk:"):
                # a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-0E-67-16:0
                meta.ts_refclk = line.split(":", 1)[1].strip()
            elif line.startswith("a=mediaclk:"):
                # a=mediaclk:direct=0
                meta.mediaclk = line.split(":", 1)[1].strip()
        
        return meta

    @staticmethod
    def load_file(file_path: str) -> StreamMetadata:
        with open(file_path, 'r', encoding='utf-8') as f:
            return SdpParser.parse(f.read())
