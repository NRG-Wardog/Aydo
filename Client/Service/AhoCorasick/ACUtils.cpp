#include "ACUtils.hpp"

#include <algorithm>
#include <botan/hex.h>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <set>

#include "../Errors.hpp"
#include "AhoCorasick.hpp"

std::string ACUtils::constraintToString(const Constraint &constraint) {
  switch (constraint) {
  case Constraint::ONE_BYTE:
    return "??";
  case Constraint::ANY_AMOUNT_OF_BYTES:
    return "*";
  default:
    return "";
  }
}

// Parses a pattern string into segments and constraints
ACUtils::PatternInfo ACUtils::parsePattern(const std::string &patternStr) {
  PatternInfo patternInfo;
  size_t pos = 0;
  size_t start = 0;

  while (pos < patternStr.length()) {
    // Look for the next constraint
    size_t constraintPos = std::string::npos;
    Constraint constraintType = Constraint::ONE_BYTE; // ! Placeholder, will be set later

    // Check for ?? constraint
    size_t anyBytePos = patternStr.find(constraintToString(Constraint::ONE_BYTE), pos);
    if (anyBytePos != std::string::npos) {
      constraintPos = anyBytePos;
      constraintType = Constraint::ONE_BYTE;
    }

    // Check for * constraint
    size_t anyAmountOfBytesPos = patternStr.find(constraintToString(Constraint::ANY_AMOUNT_OF_BYTES), pos);
    if (anyAmountOfBytesPos != std::string::npos &&
        (constraintPos == std::string::npos || anyAmountOfBytesPos < constraintPos)) {
      constraintPos = anyAmountOfBytesPos;
      constraintType = Constraint::ANY_AMOUNT_OF_BYTES;
    }

    // If we found a constraint, add the segment before it
    if (constraintPos != std::string::npos) {
      // Add the segment
      if (constraintPos > start) {
        std::string segment = patternStr.substr(start, constraintPos - start);

        auto bytes = Botan::hex_decode(segment);

        patternInfo.segments.push_back(bytes);
      }

      // Add the constraint
      if (!patternInfo.segments.empty()) {
        size_t current_segment_idx = patternInfo.segments.size() - 1;
        size_t next_segment_idx = patternInfo.segments.size();

        patternInfo.constraints.emplace_back(current_segment_idx, next_segment_idx, constraintType);
      }

      // Update the position
      start = constraintPos + constraintToString(constraintType).length();
      pos = start;
    } else {
      // Since we don't have any more constraints, after parsing the rest of the string
      // And adding it as a segment, we can break the loop
      if (start < patternStr.length()) {
        std::string segment = patternStr.substr(start, patternStr.length() - start);

        auto bytes = Botan::hex_decode(segment);

        patternInfo.segments.push_back(bytes);
      }
      break;
    }
  }

  patternInfo.patternStr = patternStr;

  return patternInfo;
}

// Helper: process Aho-Corasick matches and record start positions with base offset
void ACUtils::processMatchesAndRecordPositions(
    const std::vector<AhoCorasick::Match> &matches,
    const std::vector<std::vector<uint8_t>> &allSegments,
    size_t baseOffset,
    SegmentPositions &segmentPositions) {
  for (const auto &match : matches) {
    const auto &segment = allSegments[match.patternIndex];
    size_t startPos = baseOffset + match.startPos;

    segmentPositions[segment].push_back(startPos);
  }
}

ACUtils::SegmentPositions ACUtils::findSegmentPositionsInFile(const std::string &filePath, const std::vector<std::vector<uint8_t>> &allSegments, size_t chunkSize) {
  SegmentPositions segmentPositions;

  if (allSegments.empty()) {
    return segmentPositions;
  }

  AhoCorasick ac(allSegments);

  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    throw Errors::FailedToOpenFileException();
  }

  std::vector<uint8_t> fileContent(chunkSize);
  size_t filePos = 0;

  // Calculate maximum pattern size to determine overlap needed between chunks
  size_t maxPatternSize = 0;
  for (const auto &segment : allSegments) {
    maxPatternSize = std::max(maxPatternSize, segment.size());
  }
  size_t overlapSize = maxPatternSize > 0 ? maxPatternSize - 1 : 0;

  while (file) {
    file.read(reinterpret_cast<char *>(fileContent.data()), static_cast<std::streamsize>(chunkSize));
    size_t bytesRead = file.gcount();

    // Exit if no more data to read
    if (bytesRead == 0) {
      break;
    }

    // Search for all patterns in the current chunk using Aho Corasick
    auto matches = ac.search(fileContent.data(), bytesRead);

    // Process all matches found in this chunk using helper
    processMatchesAndRecordPositions(matches, allSegments, filePos, segmentPositions);

    if (bytesRead == chunkSize) {
      // Calculate next read position with overlap to catch patterns spanning chunks
      size_t seekPos = filePos + chunkSize - overlapSize;

      // Seek to the next position with overlap and update file position tracker
      file.seekg(static_cast<std::streamoff>(seekPos), std::ios::beg);
      filePos += chunkSize - overlapSize;
    } else {
      // Last chunk: no overlap needed, just advance by bytes read
      filePos += bytesRead;
    }
  }

  return segmentPositions;
}

ACUtils::SegmentPositions ACUtils::findSegmentPositionsInMemory(const std::vector<uint8_t> &data, const std::vector<std::vector<uint8_t>> &allSegments) {
  SegmentPositions segmentPositions;

  if (allSegments.empty()) {
    return segmentPositions;
  }

  AhoCorasick ac(allSegments);

  auto matches = ac.search(data);
  processMatchesAndRecordPositions(matches, allSegments, 0, segmentPositions);

  return segmentPositions;
}

bool ACUtils::checkConstraintSatisfaction(
    size_t currentSegmentIdx,
    size_t currentPos,
    const std::vector<std::vector<uint8_t>> &segments,
    const std::vector<std::tuple<size_t, size_t, Constraint>> &constraints,
    const SegmentPositions &segmentPositions,
    const std::function<bool(size_t, size_t)> &checkChain) {
  // Get the next segment and all its found positions
  const auto &nextSegment = segments[currentSegmentIdx + 1];
  const auto &nextPositions = segmentPositions.at(nextSegment);

  // Find the constraint type between current and next segment
  Constraint constraintType = Constraint::ONE_BYTE;
  bool wasConstraintFound = false;
  for (const auto &constraint : constraints) {
    if (std::get<0>(constraint) == currentSegmentIdx && std::get<1>(constraint) == currentSegmentIdx + 1) {
      constraintType = std::get<2>(constraint);
      wasConstraintFound = true;
      break;
    }
  }

  // Make sure a constraint was actually found
  if (!wasConstraintFound) {
    throw Errors::ConstraintNotFoundException();
  }

  // Calculate where the current segment ends
  size_t currentSegmentEnd = currentPos + segments[currentSegmentIdx].size();

  // Check if any position of the next segment satisfies the constraint
  if (std::ranges::any_of(nextPositions, [&](size_t nextPos) -> bool {
        // Skip positions that overlap with or come before the current segment
        if (nextPos < currentSegmentEnd)
          return false;

        // Calculate the gap (bytes) between segments
        size_t gap = nextPos - currentSegmentEnd;

        // Check constraint conditions:
        // - ONE_BYTE (??): requires exactly 1 byte gap
        // - ANY_AMOUNT_OF_BYTES (*): requires at least 0 byte gap
        if (constraintType == Constraint::ONE_BYTE) {
          return gap == 1 && checkChain(currentSegmentIdx + 1, nextPos);
        } else if (constraintType == Constraint::ANY_AMOUNT_OF_BYTES) {
          return checkChain(currentSegmentIdx + 1, nextPos);
        }

        // Unknown constraint
        return false;
      })) {
    // Found a valid position for the next segment
    return true;
  }

  // No valid position found for the next segment
  return false;
}

bool ACUtils::verifyPatternConstraints(const std::vector<std::vector<uint8_t>> &segments, const std::vector<std::tuple<size_t, size_t, Constraint>> &constraints, const SegmentPositions &segmentPositions) {
  if (segments.empty())
    return false;

  // Validate that all required segments are present in the position map
  for (const auto &seg : segments) {
    if (segmentPositions.find(seg) == segmentPositions.end())
      return false;
  }

  // If we have only 1 segment, make sure its not empty
  if (segments.size() == 1) {
    return !segmentPositions.at(segments[0]).empty();
  }

  std::function<bool(size_t, size_t)> checkChain = [&](size_t currentSegmentIdx, size_t currentPos) -> bool {
    // Base case: we've reached the last segment, so the chain is valid
    if (currentSegmentIdx == segments.size() - 1) {
      return true;
    }

    // Use the extracted helper function to check constraint satisfaction
    return checkConstraintSatisfaction(currentSegmentIdx, currentPos, segments, constraints, segmentPositions, checkChain);
  };

  // Start the recursive check from the first segment at position 0
  const auto &firstPositions = segmentPositions.at(segments[0]);
  return std::ranges::any_of(firstPositions, [&](size_t pos) {
    return checkChain(0, pos);
  });

  return false;
}

// Helper function to parse patterns and collect all unique segments
std::pair<std::vector<ACUtils::PatternInfo>, std::vector<std::vector<uint8_t>>> ACUtils::parsePatternsAndCollectSegments(const std::vector<std::string> &hexPatterns) {
  const size_t MAX_PRINT_PATTERN_LENGTH = 10;

  std::vector<PatternInfo> parsedPatterns;
  std::set<std::vector<uint8_t>> allSegmentsSet;

  for (const auto &hexPattern : hexPatterns) {
    try {
      PatternInfo patternInfo = parsePattern(hexPattern);

      if (!patternInfo.segments.empty()) {
        parsedPatterns.push_back(patternInfo);

        for (const auto &segment : patternInfo.segments) {
          allSegmentsSet.insert(segment);
        }
      }
    } catch (const std::exception &e) {
      std::cout << "WARNING: Couldn't parse pattern " << hexPattern.substr(0, MAX_PRINT_PATTERN_LENGTH) << "...: " << e.what() << std::endl;
    }
  }

  // Convert the set to a vector
  std::vector<std::vector<uint8_t>> allSegments(allSegmentsSet.begin(), allSegmentsSet.end());

  return std::make_pair(parsedPatterns, allSegments);
}

// Helper function with common search logic
std::pair<bool, std::string> ACUtils::searchPatternsCommon(const std::vector<PatternInfo> &parsedPatterns, const std::vector<std::vector<uint8_t>> &allSegments, const SegmentPositions &segmentPositions) {
  for (const auto &pattern : parsedPatterns) {
    if (verifyPatternConstraints(pattern.segments, pattern.constraints, segmentPositions)) {
      return std::make_pair(true, pattern.patternStr);
    }
  }

  return std::make_pair(false, "No patterns found");
}
