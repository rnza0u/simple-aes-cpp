#include <fstream>
#include <iterator>
#include <algorithm>
#include <string>

#include "utils.h"

bool compareFiles(const std::string& p1, const std::string& p2) {
  
  std::ifstream f1(p1, std::ifstream::binary|std::ifstream::ate);
  std::ifstream f2(p2, std::ifstream::binary|std::ifstream::ate);

  if (f1.fail() || f2.fail()) {
    return false;
  }

  if (f1.tellg() != f2.tellg()) {
    return false;
  }

  f1.seekg(0, std::ifstream::beg);
  f2.seekg(0, std::ifstream::beg);

  return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
    std::istreambuf_iterator<char>(),
     std::istreambuf_iterator<char>(f2.rdbuf()));
}