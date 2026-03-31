#pragma once

#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "AhoCorasick.hpp"

namespace ACUtils {
enum class Constraint : char {
  ONE_BYTE = '?',
  ANY_AMOUNT_OF_BYTES = '*'
};

// A pattern is a hex string with the following format:
// <segment [N bytes]><constraint [1/2 byte]><segment [N bytes]><constraint [1/2 byte]>...
// What this means in practice: AA BB CC (a single segment), AA BB CC DD (a single segment),
//                              AA ?? BB (two segments), AA * BB (two segments)
// `??` is a wild card, which means; any byte can be in this place
// `*` is a wild card, which means; any amount of (any) bytes can be in this place (including 0)
struct PatternInfo {
  std::string patternStr;
  std::vector<std::vector<uint8_t>> segments;
  std::vector<std::tuple<size_t, size_t, Constraint>> constraints; // <segment1 index, segment2 index, constraint>
};

using SegmentPositions = std::map<std::vector<uint8_t>, std::vector<size_t>>;

std::string constraintToString(const Constraint &constraint);

PatternInfo parsePattern(const std::string &patternStr);

SegmentPositions findSegmentPositionsInFile(const std::string &filePath, const std::vector<std::vector<uint8_t>> &allSegments, size_t chunkSize);
SegmentPositions findSegmentPositionsInMemory(const std::vector<uint8_t> &data, const std::vector<std::vector<uint8_t>> &allSegments);

// Helper: process Aho-Corasick matches and record start positions, with optional base offset
void processMatchesAndRecordPositions(
    const std::vector<AhoCorasick::Match> &matches,
    const std::vector<std::vector<uint8_t>> &allSegments,
    size_t baseOffset,
    SegmentPositions &segmentPositions);

bool verifyPatternConstraints(const std::vector<std::vector<uint8_t>> &segments, const std::vector<std::tuple<size_t, size_t, Constraint>> &constraints, const SegmentPositions &segmentPositions);
bool checkConstraintSatisfaction(
    size_t currentSegmentIdx,
    size_t currentPos,
    const std::vector<std::vector<uint8_t>> &segments,
    const std::vector<std::tuple<size_t, size_t, Constraint>> &constraints,
    const SegmentPositions &segmentPositions,
    const std::function<bool(size_t, size_t)> &checkChain);

std::pair<std::vector<PatternInfo>, std::vector<std::vector<uint8_t>>> parsePatternsAndCollectSegments(const std::vector<std::string> &hexPatterns);
std::pair<bool, std::string> searchPatternsCommon(const std::vector<PatternInfo> &parsedPatterns, const std::vector<std::vector<uint8_t>> &allSegments, const SegmentPositions &segmentPositions);

}; // namespace ACUtils
