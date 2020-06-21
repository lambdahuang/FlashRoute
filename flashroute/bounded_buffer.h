/* Copyright (C) 2019 Neo Huang - All Rights Reserved */
#pragma once

#include <boost/bind.hpp>
#include <boost/call_traits.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>

#include <boost/timer/timer.hpp>  // for auto_cpu_timer

namespace flashroute {

template <class T>
class BoundedBuffer {
 public:
  typedef boost::circular_buffer<T> ContainerType;
  typedef typename ContainerType::size_type SizeType;
  typedef typename ContainerType::value_type ValueType;
  typedef typename boost::call_traits<ValueType>::param_type param_type;

  explicit BoundedBuffer(SizeType capacity)
      : mUnread(0), mContainer(capacity) {}

  void pushFront(typename boost::call_traits<ValueType>::param_type item) {
    boost::mutex::scoped_lock lock(mMutex);
    mNotFull.wait(
        lock, boost::bind(&BoundedBuffer<ValueType>::isNotFull, this));
    mContainer.push_front(item);
    ++mUnread;
    lock.unlock();
    mNotEmpty.notify_one();
  }
  void popBack(ValueType* pItem) {
    boost::mutex::scoped_lock lock(mMutex);
    mNotEmpty.wait(
        lock, boost::bind(&BoundedBuffer<ValueType>::isNotEmpty, this));
    *pItem = mContainer[--mUnread];
    lock.unlock();
    mNotFull.notify_one();
  }

  bool empty() { return mUnread == 0; }
  SizeType size() { return mUnread; }

 private:
  BoundedBuffer(const BoundedBuffer&);  // Disabled copy constructor.
  BoundedBuffer& operator=(
      const BoundedBuffer&);  // Disabled assign operator.

  bool isNotEmpty() const { return mUnread > 0; }
  bool isNotFull() const { return mUnread < mContainer.capacity(); }

  SizeType mUnread;
  ContainerType mContainer;
  boost::mutex mMutex;
  boost::condition mNotEmpty;
  boost::condition mNotFull;
};

}  // namespace flashroute
