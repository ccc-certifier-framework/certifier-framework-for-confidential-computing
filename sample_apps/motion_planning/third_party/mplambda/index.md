# Fog Robotics Algorithms for Distributed Motion Planning Using Lambda Serverless Computing

[Jeffrey Ichnowski](https://ichnow.ski), William Lee, Victor Murta, Samuel Paradis, [Ron Alterovitz](https://www.cs.unc.edu/~ron), [Joseph E. Gonzalez](https://people.eecs.berkeley.edu/~jegonzal/), [Ion Stoica](https://people.eecs.berkeley.edu/~istoica/), [Ken Goldberg](https://goldberg.berkeley.edu/)

See our paper at ICRA 2020!

For robots using motion planning algorithms such as RRT and RRT*, the computational load can vary by orders of magnitude as the complexity of the local environment changes. To adaptively provide such computation, we propose Fog Robotics algorithms in which cloud-based serverless lambda computing provides parallel computation on demand. To use this parallelism, we propose novel motion planning algorithms that scale effectively with an increasing number of serverless computers.  However, given that the allocation of computing is typically bounded by both monetary and time constraints, we show how prior learning can be used to efficiently allocate resources at runtime.  We demonstrate the algorithms and application of learned parallel allocation in both simulation and with the Fetch commercial mobile manipulator using Amazon Lambda to complete a sequence of sporadically computationally intensive motion planning tasks.

## Conference Presentation

{% include youtubePlayer.html id="SzxeOxR_hoo" %}
