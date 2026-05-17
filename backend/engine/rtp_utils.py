class RTPUtils:
    MAX_SEQ = 65536
    MAX_DROPOUT = 3000

    @staticmethod
    def is_seq_later(s1: int, s2: int) -> bool:
        """s2 が s1 より後のシーケンス番号かを判定（折り返しを考慮）"""
        return ((s2 - s1) & 0xFFFF) < (RTPUtils.MAX_SEQ // 2)

    @staticmethod
    def count_lost(prev_seq: int, curr_seq: int) -> int:
        """前パケットと現パケット間の欠損数を返す（折り返し対応）"""
        diff = (curr_seq - prev_seq - 1) & 0xFFFF
        return diff if diff < RTPUtils.MAX_DROPOUT else 0
