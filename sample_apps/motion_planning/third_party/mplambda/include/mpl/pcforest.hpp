#pragma once
#ifndef MPL_PCFOREST_HPP
#define MPL_PCFOREST_HPP

#include "interpolate.hpp"
#include "planner.hpp"

#include <atomic>
#include <deque>
#include <random>
#include <thread>
#include <type_traits>
#include <vector>
#include <jilog.hpp>
#include <nigh/auto_strategy.hpp>

namespace mpl {
    struct PCForest {
        static constexpr bool asymptotically_optimal = true;
    };
    
    template <class Scenario>
    class Planner<Scenario, PCForest> {
    public:
        using Space = typename Scenario::Space;
        using State = typename Scenario::State;
        using Distance = typename Scenario::Distance;

        class Solution;
        
    private:
        static_assert(std::is_floating_point_v<Distance>, "distance must be a floating point type");
        
        using RNG = std::mt19937_64;
        
        class Edge;
        class Node;
        struct NodeKey;
        class Thread;

        using Concurrency = unc::robotics::nigh::Concurrent;
        using NNStrategy = unc::robotics::nigh::auto_strategy_t<Space, Concurrency>;

        using Neighborhood = std::vector<std::tuple<Node*, Distance>>;

        static constexpr Distance E = 2.71828182845904523536028747135266249775724709369995L;
        
        Scenario scenario_;

        unc::robotics::nigh::Nigh<Node*, Space, NodeKey, Concurrency, NNStrategy> nn_;

        Distance maxDistance_;
        
        Node* start_{nullptr};
        std::atomic<Edge*> solution_{nullptr};
        std::atomic_int goalBiasedSamples_{0};
        std::vector<Thread> threads_;

        Distance kRRG_;

        // State randomSample(RNG& rng, Distance goalBias) {
        //     static std::uniform_real_distribution<Distance> unif01;

        //     Edge *s = solution_.load(std::memory_order_acquire);

        //     if (s == nullptr)
        //         return (goalBias > 0 && unif01(rng) < goalBias)
        //             ? scenario_.sampleGoal(rng)
        //             : scenario_.randomSample(rng);
                
        //     State q;
        //     do {
        //         q = scenario_.randomSample(rng);
        //     } while (s->pathCost() < distance(start_->state(), q) + distance(q, s->node()->state()));
            
        //     return q;
        // }
        
        decltype(auto) nearest(const State& q) {
            return nn_.nearest(Scenario::scale(q));
        }

        void nearest(Neighborhood& nbh, const State& q) {
            unsigned k = std::ceil(kRRG_ * std::log(Distance(nn_.size() + 1)));
            nn_.nearest(nbh, Scenario::scale(q), k);
        }
        
        decltype(auto) isValid(const State& q) {
            return scenario_.isValid(q);
        }

        decltype(auto) isValid(const State& from, const State& to) {
            return scenario_.isValid(from, to);
        }

        Distance distance(const State& a, const State& b) const {
            return scenario_.space().distance(
                Scenario::scale(a), Scenario::scale(b));
        }

        decltype(auto) isGoal(const State& q) const {
            return scenario_.isGoal(q);
        }

        void addNode(Node *node) {
            nn_.insert(node);
        }

        void updateSolution(Edge *edge, bool newSample) {
            Edge *prevSolution = solution_.load(std::memory_order_acquire);
            while (prevSolution == nullptr || edge->pathCost() < prevSolution->pathCost()) {
                if (solution_.compare_exchange_weak(
                        prevSolution, edge,
                        std::memory_order_release,
                        std::memory_order_relaxed))
                {
                    const char *msg = prevSolution == nullptr
                        ? "found initial solution with cost "
                        : (edge->node() == prevSolution->node()
                           ? "solution improved, new cost "
                           : (newSample
                              ? "new solution found with cost "
                              : "solution goal reverted, new cost "));
                    JI_LOG(INFO) << msg << edge->pathCost(); //  << ", after " << elapsedSolveTime();
                    // TODO: send update to other processes
                    break;
                }
            }
        }
        
    public:
        template <class ... Args>
        Planner(Args&& ... args)
            : scenario_(std::forward<Args>(args)...)
            , nn_(scenario_.space())
            , maxDistance_(scenario_.maxSteering())
            , kRRG_{E * (1 + 1/static_cast<Distance>(scenario_.space().dimensions()))}
        {
            int nThreads = 1; //getMaxThreads(); //std::max(1, omp_get_max_threads());
            threads_.reserve(nThreads);
            std::random_device rdev;
            std::array<typename RNG::result_type, RNG::state_size> rdata;
            for (int i=0 ; i<nThreads ; ++i) {
                std::generate(rdata.begin(), rdata.end(), std::ref(rdev));
                std::seed_seq sseq(rdata.begin(), rdata.end());
                threads_.emplace_back(sseq);
            }

            setGoalBias(0.01);
        }

        const Space& space() const {
            return scenario_.space();
        }
        
        void setGoalBias(Distance d) {
            threads_[0].setGoalBias(d * threads_.size());
        }

        bool isSolved() const {
            return solution_.load(std::memory_order_relaxed) != nullptr;
        }

        void addStart(const State& q) {
            if (start_ != nullptr)
                throw std::invalid_argument("CForest only allows 1 start state");
            
            start_ = threads_[0].addStart(*this, q);
        }

        void addPath(Distance cost, const std::vector<State>& path) {
            JI_LOG(WARN) << "ADDPATH CALLED with cost=" << cost << ", waypoints=" << path.size();

            if (path.size() < 2) {
                JI_LOG(WARN) << "addPath called with path that is too short";
                return;
            }

            if (start_ == nullptr)
                throw std::invalid_argument("start state must be set before calling addPath");

            Distance dStartZero = distance(start_->state(), start_->state());
                
            if (distance(start_->state(), path.front()) > dStartZero)
                throw std::invalid_argument("addPath's start state does not match");

            auto first = path.begin();
            threads_[0].addPath(*this, start_, ++first, path.end());
        }

        std::size_t size() const {
            return nn_.size();
        }

        int goalBiasedSamples() const {
            return goalBiasedSamples_;
        }

    private:
        template <class T, class Fn>
        T threadAccum(T init, Fn fn) const {
            return std::accumulate(threads_.begin(), threads_.end(), init, fn);
        }

    public:
        int samplesConsidered() const {
            return threadAccum(0, [&] (int a, const auto& t) { return a + t.samples(); });
        }

        int rejectedSamples() const {
            return threadAccum(0, [&] (int a, const auto& t) { return a + t.rejectedSamples(); });
        }

        Solution solution() const {
            return solution_.load(std::memory_order_acquire);
        }

        template <class DoneFn>
        void solve(DoneFn doneFn) {
            if (!start_)
                throw std::logic_error("start state must be set before calling solve()");
            
            int nThreads = threads_.size();
            JI_LOG(INFO) << "solving on " << nThreads << " threads";
            std::atomic_bool done{false};
#ifdef USE_OPENMP
#pragma omp parallel for shared(done) schedule(static, 1) num_threads(nThreads)
            for (int i=0 ; i<nThreads ; ++i) {
                try {
                    if (int tNo = omp_get_thread_num()) {
                        threads_[tNo].solve(*this, [&] { return done.load(std::memory_order_relaxed); });
                    } else {
                        threads_[0].solve(*this, doneFn);
                        done.store(true);
                    }
                } catch (const std::exception& ex) {
                    JI_LOG(ERROR) << "solve died with exception: " << ex.what();
                }
            }
#else
            auto workerDone = [&] { return done.load(std::memory_order_relaxed); };

            for (int i=1 ; i<nThreads ; ++i)
                threads_[i].thread_ = std::thread(
                    [&,i] () { threads_[i].solve(*this, workerDone); });

            try {
                threads_[0].solve(*this, doneFn);
                done.store(true);
            } catch (const std::exception& ex) {
                JI_LOG(ERROR) << "solve died with exception: " << ex.what();
            }

            for (int i=1 ; i<nThreads ; ++i)
                threads_[i].thread_.join();
#endif
        }

        template <class Visitor>
        void visitTree(Visitor visitor) const {
            for (const auto& t : threads_)
                t.visitTree(visitor);
        }
    };

    template <class Scenario>
    class Planner<Scenario, PCForest>::Node {
        State state_;
        std::atomic<Edge*> edge_;
        bool goal_;

    public:
        Node(const Node&) { abort(); }
        Node(Node&&) { abort(); }
        Node(bool goal, const State& q)
            : state_(q)
            , edge_{nullptr}
            , goal_(goal)
        {
        }
        
        bool isGoal() const {
            return goal_;
        }

        const State& state() const {
            return state_;
        }

        Edge* edge(std::memory_order mo) {
            return edge_.load(mo);
        }

        const Edge* edge() const {
            return edge_.load(std::memory_order_acquire);
        }

        bool casEdge(Edge *expect, Edge *value, std::memory_order success, std::memory_order failure) {
            return edge_.compare_exchange_weak(expect, value, success, failure);
        }
    };

    template <class Scenario>
    class Planner<Scenario, PCForest>::Edge {
        Node *node_;
        Edge *parent_;
        Distance edgeCost_;
        Distance pathCost_;

        std::atomic<Edge*> firstChild_{nullptr};
        std::atomic<Edge*> nextSibling_{nullptr};

        void addChild(Edge *child) {
            Edge *next = firstChild_.load(std::memory_order_relaxed);
            do {
                child->nextSibling_.store(next, std::memory_order_relaxed);
            } while (!firstChild_.compare_exchange_weak(
                         next, child,
                         std::memory_order_release,
                         std::memory_order_relaxed));
        }

    public:
        Edge(const Edge&) { abort(); }
        Edge(Edge&&) { abort(); }

        Edge(Node *node)
            : node_(node)
            , parent_(nullptr)
            , edgeCost_(0)
            , pathCost_(0)
        {
        }

        Edge(Node *node, Edge *parent, Distance edgeCost, Distance pathCost)
            : node_(node)
            , parent_(parent)
            , edgeCost_(edgeCost)
            , pathCost_(pathCost)
        {
            assert(parent->pathCost_ + edgeCost == pathCost_);
            parent->addChild(this);
        }

        Node* node() {
            return node_;
        }

        const Node* node() const {
            return node_;
        }

        Distance pathCost() const {
            return pathCost_;
        }
        
        Distance edgeCost() const {
            return edgeCost_;
        }

        const Edge *parent() const {
            return parent_;
        }

        Edge *firstChild(std::memory_order order) {
            return firstChild_.load(order);
        }

        Edge *nextSibling(std::memory_order order) {
            return nextSibling_.load(order);
        }

        bool casFirstChild(Edge*& expect, Edge* value, std::memory_order success, std::memory_order failure) {
            return firstChild_.compare_exchange_weak(expect, value, success, failure);
        }
    };

    template <class Scenario>
    class Planner<Scenario, PCForest>::Solution {
    public:
        using State = typename Scenario::State;
        using Distance = typename Scenario::Distance;
        
    private:
        const Edge *edge_;

        friend class Planner;
        
        Solution(const Edge *edge) : edge_(edge) {}

    public:
        Solution() : edge_{nullptr} {}
        
        operator bool () const {
            return edge_ != nullptr;
        }

        Distance cost() const {
            return edge_ ? edge_->pathCost() : std::numeric_limits<Distance>::infinity();
        }

        template <class Fn>
        void visit(Fn fn) const {
            for (const Edge *e = edge_ ; e != nullptr ; e = e->parent())
                fn(e->node()->state());
        }

        bool operator == (const Solution& other) const {
            return edge_ == other.edge_;
        }

        bool operator != (const Solution& other) const {
            return edge_ != other.edge_;
        }

        bool operator < (const Solution& other) const {
            return cost() < other.cost();
        }

        bool operator > (const Solution& other) const {
            return other < *this;
        }

        bool operator <= (const Solution& other) const {
            return !(other < *this);
        }

        bool operator >= (const Solution& other) const {
            return !(*this < other);
        }
    };

    template <class Scenario>
    struct Planner<Scenario, PCForest>::NodeKey {
        State operator() (const Node* node) const {
            return Scenario::scale(node->state());
        }
    };

    template <class Scenario>
    class Planner<Scenario, PCForest>::Thread {
        using ParentCandidate = std::tuple<Distance, Edge*, std::size_t>;
        
        struct ParentHeapCompare {
            bool operator() (const ParentCandidate& a, const ParentCandidate& b) {
                return std::get<Distance>(a) > std::get<Distance>(b);
            }
        };
        
        RNG rng_;
        std::deque<Node> nodes_;
        std::deque<Edge> edges_;
        Neighborhood nbh_;
        std::vector<ParentCandidate> parentHeap_;

        Distance goalBias_{0};
        int samples_{0};
        int rejectedSamples_{0};

#ifndef USE_OPENMP
    public:
        std::thread thread_;
#endif

    public:
        Thread(Thread&& other)
            : rng_(std::move(other.rng_))
            , nodes_(std::move(other.nodes_))
            , edges_(std::move(other.edges_))
            , nbh_(std::move(other.nbh_))
            , parentHeap_(std::move(other.parentHeap_))
            , goalBias_(other.goalBias_)
            , samples_(other.samples_)
            , rejectedSamples_(other.rejectedSamples_)
        {
        }
        
        template <class SSeq>
        Thread(SSeq& sseq)
            : rng_(sseq)
        {
        }

        int samples() const {
            return samples_;
        }

        int rejectedSamples() const {
            return rejectedSamples_;
        }

        void setGoalBias(Distance d) {
            JI_LOG(TRACE) << "thread goal bias set to " << d;
            goalBias_ = d;
        }

        Node* addStart(Planner& planner, const State& q) {
            if (!planner.isValid(q)){
                throw std::invalid_argument("start state is not valid");
            }
            
            bool isGoal = planner.isGoal(q);
            Node *newNode = &nodes_.emplace_back(isGoal, q);
            Edge *newEdge = &edges_.emplace_back(newNode);
            setEdge(planner, newNode, newEdge);
            planner.addNode(newNode);
            return newNode;
        }

        Node* addSample(Planner& planner, State qRand, bool knownGoal) {
            auto [nNear, dNear] = planner.nearest(qRand).value();

            if (dNear > planner.maxDistance_) {
                qRand = interpolate(nNear->state(), qRand, planner.maxDistance_ / dNear);
                dNear = planner.distance(nNear->state(), qRand);
                knownGoal = false; // we no longer know that this is a goal
            }

            if (dNear == 0 || dNear == planner.distance(qRand, qRand))
                return nullptr;

            if (!planner.isValid(nNear->state(), qRand))
                return nullptr;

            Node *newNode = &nodes_.emplace_back(knownGoal || planner.isGoal(qRand), qRand);
            addNodeNear(planner, newNode, nNear, dNear);
            return newNode;
        }

        void addNodeNear(Planner& planner, Node *newNode, Node *nNear, Distance dNear) {
            Edge *parent = nNear->edge(std::memory_order_relaxed);
            Distance parentCost = parent->pathCost() + dNear;

            // get the neighborhood for rewiring
            planner.nearest(nbh_, newNode->state());

            // check if any in the neighborhood would make a better
            // parent than the current one.  We check in increasing
            // order of pathCost up to the pathCost of the nearest
            // node.
            parentHeap_.clear();
            for (std::size_t nbrIndex=0 ; nbrIndex<nbh_.size() ; ++nbrIndex) {
                auto [ nbrNode, nbrDist ] = nbh_[nbrIndex];
                Edge *nbrEdge = nbrNode->edge(std::memory_order_acquire);
                Distance nbrPathCost = nbrEdge->pathCost() + nbrDist;
                if (nbrPathCost >= parentCost)
                    break;
                parentHeap_.emplace_back(nbrPathCost, nbrEdge, nbrIndex);
            }
            std::make_heap(parentHeap_.begin(), parentHeap_.end(), ParentHeapCompare{});
            while (!parentHeap_.empty()) {
                auto [ nbrPathCost, nbrEdge, nbrIndex ] = parentHeap_.front();
                std::get<Node*>(nbh_[nbrIndex]) = nullptr; // mark neighbor as already checked
                if (planner.isValid(nbrEdge->node()->state(), newNode->state())) {
                    parent = nbrEdge;
                    dNear = std::get<Distance>(nbh_[nbrIndex]);
                    parentCost = nbrPathCost;
                    break;
                }
                std::pop_heap(parentHeap_.begin(), parentHeap_.end(), ParentHeapCompare{});
                parentHeap_.pop_back();
            }

            // Now that we have the parent, we can add the node to the
            // tree.  After this, other threads may access the node.
            Edge *newEdge = &edges_.emplace_back(newNode, parent, dNear, parentCost);
            setEdge(planner, newNode, newEdge);
            planner.addNode(newNode);

            if (newNode->isGoal())
                planner.updateSolution(newEdge, true);

            // last stage of rewiring, check to see if any neighboring
            // nodes can be rewired to have a shorter path through the
            // new node.
            for (auto it = nbh_.rbegin() ; it != nbh_.rend() ; ++it) {
                auto [ nbrNode, nbrDist ] = *it;

                // if nbrNode is null then we already checked it for
                // rewiring as a parent and rejected it since it could
                // not connect to the new node.
                if (nbrNode == nullptr)
                    continue;

                Edge *nbrEdge = nbrNode->edge(std::memory_order_acquire);
                Distance newCost = parentCost + nbrDist;
                if (newCost < nbrEdge->pathCost() && planner.isValid(newNode->state(), nbrNode->state()))
                    setEdge(planner, nbrNode, &edges_.emplace_back(nbrNode, newEdge, nbrDist, newCost));
            }
        }

        void setEdge(Planner& planner, Node* node, Edge* newEdge) {
            Edge *oldEdge = node->edge(std::memory_order_relaxed);
            for (;;) {
                if (oldEdge && oldEdge->pathCost() <= newEdge->pathCost()) {
                    std::swap(oldEdge, newEdge);
                    break;
                }

                if (node->casEdge(oldEdge, newEdge, std::memory_order_release, std::memory_order_relaxed))
                    break;
            }

            if (node->isGoal())
                planner.updateSolution(newEdge, false);

            if (oldEdge == nullptr)
                return;

            do {
                Edge *firstChild = oldEdge->firstChild(std::memory_order_relaxed);
                while (!oldEdge->casFirstChild(
                           firstChild, nullptr,
                           std::memory_order_release,
                           std::memory_order_relaxed))
                    ;
                for (Edge *oldChild = firstChild ; oldChild ; oldChild = oldChild->nextSibling(std::memory_order_acquire)) {
                    Node *childNode = oldChild->node();
                    Edge *shorterEdge = &edges_.emplace_back(
                        childNode, newEdge, oldChild->edgeCost(), newEdge->pathCost() + oldChild->edgeCost());
                    setEdge(planner, childNode, shorterEdge);
                }
                oldEdge = newEdge;
                newEdge = node->edge(std::memory_order_acquire);
            } while (oldEdge != newEdge);
        }

        template <class Iter>
        void addPath(Planner& planner, Node* prev, Iter first, Iter last) {
            // path.front() should be the start state
            // path.back() should be a/the goal state

            // we know that each path segment is valid, thus we do not
            // need to check.  We also know that each path segment is
            // the likely candidate for a parent, and can thus skip
            // the first nearest neighbor search.

            for (Iter it = first ; it != last ; ++it) {
                Distance dPrev = planner.distance(prev->state(), *it);
                auto [nNear, dNear] = planner.nearest(*it).value();
                
                // check if the nearest node is distance of 0 away
                // (using distance to self to compute 0 to account for
                // floating point inaccuracies)
                if (dNear > planner.distance(*it, *it)) {
                    // the state is not already in the graph, we have
                    // to add it.
                    bool isGoal = (it+1 == last); // the last element in the path is a goal
                    Node *newNode = &nodes_.emplace_back(isGoal, *it);
                    addNodeNear(planner, newNode, prev, dPrev);
                    prev = newNode;
                } else {
                    // the path state is already in the graph, however
                    // it may not have the best path to it.  We check
                    // only the prev node, which we know is a valid
                    // parent, and see if an edge through it would
                    // make a better path for the existing node.  Only
                    // then do we replace the edge.  We do not (though
                    // we could consider) do any neighborhood
                    // rewiring.

                    Edge* prevEdge = prev->edge(std::memory_order_acquire);
                    Distance newCost = prevEdge->pathCost() + dPrev;
                    if (newCost < nNear->edge(std::memory_order_acquire)->pathCost()) {
                        Edge *newEdge = &edges_.emplace_back(nNear, prevEdge, dPrev, newCost);
                        setEdge(planner, nNear, newEdge);
                    }
                    prev = nNear;
                }
            }
        }

        void addRandomSample(Planner& planner) {
            static std::uniform_real_distribution<Distance> unif01;

            ++samples_;
            
            Edge *s = planner.solution_.load(std::memory_order_acquire);

            if (Scenario::multiGoal || s == nullptr) {
                if (goalBias_ > 0 && unif01(rng_) < goalBias_) {
                    if (auto q = planner.scenario_.sampleGoal(rng_)) {
                        ++planner.goalBiasedSamples_;
                        addSample(planner, *q, true);
                        return;
                    }
                }
                addSample(planner, planner.scenario_.randomSample(rng_), false);
            } else {
                State q = planner.scenario_.randomSample(rng_);
                while (s->pathCost() <
                       planner.distance(planner.start_->state(), q) +
                       planner.distance(q, s->node()->state())) {
                    ++rejectedSamples_;
                    q = planner.scenario_.randomSample(rng_);
                }

                addSample(planner, q, false);
            }
        }

        template <class DoneFn>
        void solve(Planner& planner, DoneFn done) {
            while (!done())
                addRandomSample(planner);
        }

        template <class Visitor>
        void visitTree(Visitor& visitor) const {
            for (const Node& n : nodes_)
                if (const Edge *p = n.edge()->parent())
                    visitor(n.state(), p->node()->state());
        }
    };
}

#endif
